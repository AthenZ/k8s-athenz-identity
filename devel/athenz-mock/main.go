package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"path/filepath"
	"syscall"

	"github.com/dimfeld/httptreemux"
	"github.com/yahoo/k8s-athenz-identity/internal/tlsutil"
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
	tls           *tls.Config
	handler       http.Handler
	rootCAHandler http.Handler
	shutdownGrace time.Duration
	closers       []io.Closer
}

func (p *params) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func envOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

func parseFlags(program string, args []string) (*params, error) {
	var (
		addr          = envOrDefault("ADDR", ":4443")
		caAddr        = envOrDefault("CA_ADDR", ":4080")
		authHeader    = envOrDefault("AUTH_HEADER", "Athenz-Principal-Auth")
		rootKeyFile   = envOrDefault("ROOT_CA_KEY_FILE", "/var/athenz/root-ca/key")
		rootCertFile  = envOrDefault("ROOT_CA_CERT_FILE", "/var/athenz/root-ca/cert")
		keyFile       = envOrDefault("KEY_FILE", "/var/athenz/server/server.key")
		certFile      = envOrDefault("CERT_FILE", "/var/athenz/server/server.cert")
		dnsSuffix     = envOrDefault("DNS_SUFFIX", "example.cloud")
		shutdownGrace = envOrDefault("SHUTDOWN_GRACE", "10s")
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

	config, closer, err := tlsutil.ServerConfig(tlsutil.Config{
		KeyFile:    keyFile,
		CertFile:   certFile,
		CACertFile: rootCertFile, // slightly weird
	})
	if err != nil {
		return nil, err
	}
	rootKeyBytes, err := ioutil.ReadFile(rootKeyFile)
	if err != nil {
		return nil, err
	}
	rootCertBytes, err := ioutil.ReadFile(rootCertFile)
	if err != nil {
		return nil, err
	}
	myCertBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	z, err := newZTS(authHeader, rootCertBytes, rootKeyBytes, dnsSuffix)
	if err != nil {
		return nil, err
	}

	rootCAHandler := httptreemux.New()
	rootCAHandler.GET("/ca", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		w.Header().Set("Context-Type", "text/plain")
		w.Write(myCertBytes)
	})

	return &params{
		addr:          addr,
		caAddr:        caAddr,
		tls:           config,
		handler:       z.handler(ztsPath),
		rootCAHandler: rootCAHandler,
		shutdownGrace: sg,
		closers:       []io.Closer{closer},
	}, nil
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer params.Close()

	server := &http.Server{
		Addr:      params.addr,
		Handler:   params.handler,
		TLSConfig: params.tls,
	}

	caServer := &http.Server{
		Addr:    params.caAddr,
		Handler: params.rootCAHandler,
	}
	done := make(chan error, 2)
	go func() {
		done <- server.ListenAndServeTLS("", "")
	}()
	go func() {
		done <- caServer.ListenAndServe()
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
