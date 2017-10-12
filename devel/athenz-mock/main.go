package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const ztsPath = "/zts/v1"

var errEarlyExit = errors.New("early exit")

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
	caAddr        string
	keyFile       string
	certFile      string
	handler       http.Handler
	shutdownGrace time.Duration
	closers       []io.Closer
}

func (p *params) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func parseFlags(program string, args []string) (*params, error) {
	var (
		addr          = util.EnvOrDefault("ADDR", ":4443")
		caAddr        = util.EnvOrDefault("CA_ADDR", ":4080")
		authHeader    = util.EnvOrDefault("AUTH_HEADER", "Athenz-Principal-Auth")
		rootKeyFile   = util.EnvOrDefault("ROOT_CA_KEY_FILE", "/var/athenz/root-ca/key")
		rootCertFile  = util.EnvOrDefault("ROOT_CA_CERT_FILE", "/var/athenz/root-ca/cert")
		keyFile       = util.EnvOrDefault("KEY_FILE", "/var/athenz/server/server.key")
		certFile      = util.EnvOrDefault("CERT_FILE", "/var/athenz/server/server.cert")
		dnsSuffix     = util.EnvOrDefault("DNS_SUFFIX", "example.cloud")
		shutdownGrace = util.EnvOrDefault("SHUTDOWN_GRACE", "10s")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&addr, "listen", addr, "[<ip>]:<port> to listen on")
	f.StringVar(&caAddr, "ca-listen", caAddr, "[<ip>]:<port> to serve root CA from /ca path")
	f.StringVar(&rootKeyFile, "root-ca-key", rootKeyFile, "path to root CA TLS key")
	f.StringVar(&rootCertFile, "root-ca-cert", rootCertFile, "path to root CA TLS cert")
	f.StringVar(&keyFile, "key", keyFile, "path to TLS key")
	f.StringVar(&certFile, "cert", certFile, "path to TLS cert")
	f.StringVar(&dnsSuffix, "dns-suffix", dnsSuffix, "DNS suffix for CSR SAN name")
	f.StringVar(&shutdownGrace, "shutdown-grace", shutdownGrace, "grace period for connections to drain at shutdown")
	f.StringVar(&authHeader, "auth-header", authHeader, "auth header")

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

	sg, err := time.ParseDuration(shutdownGrace)
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown grace %q, %v", shutdownGrace, err)
	}

	rootKeyBytes, err := ioutil.ReadFile(rootKeyFile)
	if err != nil {
		return nil, err
	}
	rootCertBytes, err := ioutil.ReadFile(rootCertFile)
	if err != nil {
		return nil, err
	}
	z, err := newZTS(authHeader, rootCertBytes, rootKeyBytes, dnsSuffix)
	if err != nil {
		return nil, err
	}

	return &params{
		addr:          addr,
		keyFile:       keyFile,
		certFile:      certFile,
		caAddr:        caAddr,
		handler:       z.handler(ztsPath),
		shutdownGrace: sg,
	}, nil
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer params.Close()

	server := &http.Server{
		Addr:    params.addr,
		Handler: params.handler,
	}

	done := make(chan error, 2)
	go func() {
		done <- server.ListenAndServeTLS(params.certFile, params.keyFile)
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
			stopChan = nil // prevent additional channel firing
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
