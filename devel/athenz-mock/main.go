// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

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

	"github.com/ghodss/yaml"
	"github.com/yahoo/k8s-athenz-identity/devel/mock"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
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
		rootKeyFile   = util.EnvOrDefault("ROOT_CA_KEY_FILE", "/var/athenz/root-ca/key")
		rootCertFile  = util.EnvOrDefault("ROOT_CA_CERT_FILE", "/var/athenz/root-ca/cert")
		keyFile       = util.EnvOrDefault("KEY_FILE", "/var/athenz/server/server.key")
		certFile      = util.EnvOrDefault("CERT_FILE", "/var/athenz/server/server.cert")
		shutdownGrace = util.EnvOrDefault("SHUTDOWN_GRACE", "10s")
		ztsConfig     = util.EnvOrDefault("ZTS_CONFIG", "/var/zts/config.yaml")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&addr, "listen", addr, "[<ip>]:<port> to listen on")
	f.StringVar(&rootKeyFile, "root-ca-key", rootKeyFile, "path to root CA TLS key")
	f.StringVar(&rootCertFile, "root-ca-cert", rootCertFile, "path to root CA TLS cert")
	f.StringVar(&keyFile, "key", keyFile, "path to TLS key")
	f.StringVar(&certFile, "cert", certFile, "path to TLS cert")
	f.StringVar(&ztsConfig, "zts-config", ztsConfig, "path to ZTS config file")
	f.StringVar(&shutdownGrace, "shutdown-grace", shutdownGrace, "grace period for connections to drain at shutdown")
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

	cc, err := cp()
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(ztsConfig)
	if err != nil {
		return nil, err
	}
	var zc mock.ZTSConfig
	if err := yaml.Unmarshal(b, &zc); err != nil {
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

	sg, err := time.ParseDuration(shutdownGrace)
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown grace %q, %v", shutdownGrace, err)
	}

	// we talk to the provider using our identity and make sure provider
	// is running with our CA certs
	clientTLS, closer, err := cc.ClientTLSConfigWithCreds(config.Credentials{
		KeyFile:  keyFile,
		CertFile: certFile,
	}, config.ServiceRoot)
	if err != nil {
		return nil, err
	}

	z, err := newZTS(clientTLS, rootCertBytes, rootKeyBytes, cc, &zc)
	if err != nil {
		return nil, err
	}

	return &params{
		addr:          addr,
		keyFile:       keyFile,
		certFile:      certFile,
		handler:       util.NewAccessLogHandler(z.handler(ztsPath)),
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
