// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

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

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/services/ident"
	"github.com/yahoo/k8s-athenz-identity/internal/services/keys"
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
		signingKeyDir     = util.EnvOrDefault("SIGNING_KEYS_DIR", "/var/keys/private")
		secretName        = util.EnvOrDefault("SECRET_PREFIX", "athenz-init-secret")
		podEndpoint       = util.EnvOrDefault("POD_ENDPOINT", "")
		driverSource      = util.EnvOrDefault("DRIVER_SOURCE", "/usr/bin/athenz-volume-driver")
		driverTarget      = util.EnvOrDefault("DRIVER_TARGET", "/drivers/athenz-volume-driver")
		podServiceTimeout = util.EnvOrDefault("POD_TIMEOUT", "10s")
		tokenExpiry       = util.EnvOrDefault("TOKEN_EXPIRY", "5m")
		shutdownGrace     = util.EnvOrDefault("SHUTDOWN_GRACE", "10s")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&addr, "listen", addr, "unix socket or TCP port to listen")
	f.StringVar(&podEndpoint, "pod-endpoint", podEndpoint, "URL for kubelet read service")
	f.StringVar(&clientKeyFile, "key", clientKeyFile, "path to client TLS key")
	f.StringVar(&clientCertFile, "cert", clientCertFile, "path to client TLS cert")
	f.StringVar(&signingKeyDir, "sign-key-dir", signingKeyDir, "directory containing signing keys")
	f.StringVar(&secretName, "secret-name", secretName, "file prefix for private key files")
	f.StringVar(&tokenExpiry, "token-expiry", tokenExpiry, "token expiry for JWTs")
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
	}); err != nil {
		return nil, err
	}

	sg, err := time.ParseDuration(shutdownGrace)
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown grace %q, %v", shutdownGrace, err)
	}
	pt, err := time.ParseDuration(podServiceTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid pod service timeout %q, %v", podServiceTimeout, err)
	}
	te, err := time.ParseDuration(tokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("invalid token expiry %q, %v", tokenExpiry, err)
	}

	cc, err := cp()
	if err != nil {
		return nil, errors.Wrap(err, "load cluster config")
	}

	l := &lookup{
		podEndpoint: os.ExpandEnv(podEndpoint),
		timeout:     pt,
		mapper:      identity.NewMapper(cc),
	}

	privateSource := keys.NewPrivateKeySource(signingKeyDir, secretName)

	sc := identity.SerializerConfig{
		TokenExpiry: te,
		KeyProvider: privateSource.SigningKey,
	}
	ser, err := identity.NewSerializer(sc)
	if err != nil {
		return nil, errors.Wrap(err, "serializer creation")
	}

	handler, err := ident.NewHandler(apiVersion, ident.HandlerConfig{
		Signer:        ser.IdentityDoc,
		AttrProvider:  l.getPodAttributes,
		ZTSEndpoint:   cc.ZTSEndpoint,
		ClusterConfig: cc,
	})
	if err != nil {
		return nil, errors.Wrap(err, "ident.NewHandler")
	}
	return &params{
		addr:          addr,
		handler:       util.NewAccessLogHandler(handler, nil),
		shutdownGrace: sg,
		driverSource:  driverSource,
		driverTarget:  driverTarget,
		closers:       []io.Closer{},
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
