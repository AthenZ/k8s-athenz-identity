package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"net"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/services/ident"
	"github.com/yahoo/k8s-athenz-identity/internal/services/jwt"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const apiVersion = "/v1"

var errEarlyExit = fmt.Errorf("early exit")

// Version gets set by the build script via LDFLAGS
var Version string

func getVersion() string {
	if Version == "" {
		return "development version"
	}
	return Version
}

type params struct {
	addr          string
	handler       http.Handler
	shutdownGrace time.Duration
	closers       []io.Closer
	driverSource  string
	driverTarget  string
}

func (p *params) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func parseFlags(program string, args []string) (*params, error) {
	var (
		addr              = util.EnvOrDefault("ADDR", "")
		clientKeyFile     = util.EnvOrDefault("KEY_FILE", "")
		clientCertFile    = util.EnvOrDefault("CERT_FILE", "")
		podEndpoint       = util.EnvOrDefault("POD_ENDPOINT", "")
		jwtEndpoint       = util.EnvOrDefault("JWT_ENDPOINT", "")
		driverSource      = util.EnvOrDefault("DRIVER_SOURCE", "/usr/bin/athenz-volume-driver")
		driverTarget      = util.EnvOrDefault("DRIVER_TARGET", "/drivers/athenz-volume-driver")
		podServiceTimeout = util.EnvOrDefault("POD_TIMEOUT", "10s")
		jwtServiceTimeout = util.EnvOrDefault("JWT_TIMEOUT", "10s")
		shutdownGrace     = util.EnvOrDefault("SHUTDOWN_GRACE", "10s")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&addr, "listen", addr, "unix socket or TCP port to listen")
	f.StringVar(&podEndpoint, "pod-endpoint", podEndpoint, "URL for kubelet read service")
	f.StringVar(&jwtEndpoint, "jwt-endpoint", jwtEndpoint, "URL for JWT service including version path")
	f.StringVar(&clientKeyFile, "key", clientKeyFile, "path to client TLS key")
	f.StringVar(&clientCertFile, "cert", clientCertFile, "path to client TLS cert")
	f.StringVar(&jwtServiceTimeout, "jwt-service-timeout", jwtServiceTimeout, "service timeout for JWT service")
	f.StringVar(&podServiceTimeout, "pod-service-timeout", podServiceTimeout, "service timeout for pod service")
	f.StringVar(&shutdownGrace, "shutdown-grace", shutdownGrace, "grace period for connections to drain at shutdown")
	f.StringVar(&driverSource, "driver-source", driverSource, "source path of driver file in container")
	f.StringVar(&driverTarget, "driver-target", driverTarget, "target host path of driver file as mounted in container")
	cp := config.CmdLine(f)

	var showVersion bool
	f.BoolVar(&showVersion, "version", false, "Show version information")

	err := f.Parse(args)
	if err != nil {
		if err == flag.ErrHelp {
			err = errEarlyExit
		}
		return nil, err
	}

	if showVersion {
		fmt.Println(getVersion())
		return nil, errEarlyExit
	}

	if err := util.CheckFields("arguments", map[string]bool{
		"listen":       addr == "",
		"key":          clientKeyFile == "",
		"cert":         clientCertFile == "",
		"pod-endpoint": podEndpoint == "",
		"jwt-endpoint": jwtEndpoint == "",
	}); err != nil {
		return nil, err
	}

	sg, err := time.ParseDuration(shutdownGrace)
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown grace %q, %v", shutdownGrace, err)
	}
	jt, err := time.ParseDuration(jwtServiceTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT service timeout %q, %v", jwtServiceTimeout, err)
	}
	pt, err := time.ParseDuration(podServiceTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid pod service timeout %q, %v", podServiceTimeout, err)
	}

	cc, err := cp()
	if err != nil {
		return nil, errors.Wrap(err, "load cluster config")
	}
	cfg, closer, err := cc.ClientTLSConfigWithCreds(config.Credentials{
		KeyFile:  clientKeyFile,
		CertFile: clientCertFile,
	}, config.ServiceRoot)
	if err != nil {
		return nil, err
	}

	client := jwt.NewClient(jwtEndpoint, &http.Client{
		Timeout: jt,
		Transport: &http.Transport{
			TLSClientConfig: cfg,
		},
	})
	serviceIPProvider := func(domain, service string) (x string, _ error) {
		defer func() {
			log.Println("SIP for ", domain, "/", service, "=", x, err)
		}()
		host := cc.ServiceURLHost(domain, service)
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				if ip.To4() != nil {
					return ip.String(), nil
				}
			}
		}
		return "", nil
	}
	l := &lookup{
		podEndpoint: os.ExpandEnv(podEndpoint),
		timeout:     pt,
		mapper:      identity.NewMapper(cc, serviceIPProvider),
	}

	handler, err := ident.NewHandler(apiVersion, ident.HandlerConfig{
		Signer:          client.GetJWT,
		AttrProvider:    l.getPodAttributes,
		ZTSEndpoint:     cc.ZTSEndpoint,
		ClusterConfig:   cc,
		ProviderService: cc.ProviderService,
		DNSSuffix:       cc.DNSSuffix,
	})
	if err != nil {
		return nil, errors.Wrap(err, "ident.NewHandler")
	}
	return &params{
		addr:          addr,
		handler:       util.NewAccessLogHandler(handler),
		shutdownGrace: sg,
		driverSource:  driverSource,
		driverTarget:  driverTarget,
		closers:       []io.Closer{closer},
	}, nil
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer params.Close()

	// copy the volume driver binary safely, if needed
	// TODO: this might need retry if old version of binary is in use
	if params.driverTarget != "" {
		log.Println("Copy", params.driverSource, "to", params.driverTarget)
		w := util.NewWriter()
		err := w.AddFile(params.driverTarget, 0755, params.driverSource)
		if err != nil {
			return errors.Wrap(err, "writer.AddFile")
		}
		if err := w.Save(); err != nil {
			return errors.Wrap(err, "writer.Save")
		}
	}

	listener, err := util.NewListener(params.addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: params.handler,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()

	stopped := false
	for {
		select {
		case err := <-done:
			if stopped {
				return nil
			}
			return err
		case <-stopChan:
			stopChan = nil
			stopped = true
			ctx, fn := context.WithTimeout(context.Background(), params.shutdownGrace)
			defer fn()
			server.Shutdown(ctx)
		}
	}
}

func main() {
	flag.CommandLine.Parse([]string{}) // initialize glog with defaults
	stopChan := make(chan struct{})
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-ch
		log.Println("shutting down...")
		close(stopChan)
	}()

	err := run(filepath.Base(os.Args[0]), os.Args[1:], stopChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln("[FATAL]", err)
	}
}
