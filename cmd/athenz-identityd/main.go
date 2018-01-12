// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/dimfeld/httptreemux"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

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
	tls           *tls.Config
	closers       []io.Closer
}

func (p *params) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func parseFlags(clusterConfig *rest.Config, program string, args []string) (*params, error) {
	var (
		addr          = util.EnvOrDefault("ADDR", ":4443")
		keyFile       = util.EnvOrDefault("KEY_FILE", "/var/tls/athenz/private/service.key")
		certFile      = util.EnvOrDefault("CERT_FILE", "/var/tls/athenz/public/service.cert")
		publicKeyDir  = util.EnvOrDefault("PUBLIC_KEYS_DIR", "/var/keys/public")
		ztsCommonName = util.EnvOrDefault("ZTS_COMMON_NAME", "zts.example.cloud")
		shutdownGrace = util.EnvOrDefault("SHUTDOWN_GRACE", "10s")
		secretName    = util.EnvOrDefault("SECRET_PREFIX", "athenz-init-secret")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&addr, "listen", addr, "[<ip>]:<port> to listen on")
	f.StringVar(&keyFile, "key", keyFile, "path to key file")
	f.StringVar(&certFile, "cert", certFile, "path to cert file")
	f.StringVar(&publicKeyDir, "sign-pub-dir", publicKeyDir, "directory containing public signing keys")
	f.StringVar(&secretName, "secret-name", secretName, "file prefix for public key files")
	f.StringVar(&ztsCommonName, "zts-name", ztsCommonName, "common name to verify in Athenz TLS cert")
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

	sg, err := time.ParseDuration(shutdownGrace)
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown grace %q, %v", shutdownGrace, err)
	}

	cc, err := cp()
	if err != nil {
		return nil, err
	}

	if clusterConfig == nil {
		clusterConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	cs, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create clientset, %v", err)
	}

	watcher, err := util.NewPodWatcher("", cs, util.PodWatchConfig{})
	if err != nil {
		return nil, fmt.Errorf("create pod watcher: %v", err)
	}
	watcher.Start()

	publicSource := util.NewPublicKeySource(publicKeyDir, secretName)
	mapper := identity.NewMapper(cc)
	verifier, err := identity.NewVerifier(identity.VerifierConfig{
		AttributeProvider: func(podID string) (*identity.PodSubject, error) {
			pod, err := watcher.PodForKey(podID)
			if err != nil {
				return nil, err
			}
			return mapper.GetSubject(pod)
		},
		PublicKeyProvider: publicSource.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	conf, closer, err := cc.ServerTLSConfig(
		config.Credentials{
			KeyFile:  keyFile,
			CertFile: certFile,
		},
		config.VerifyClient{
			Source: config.AthenzRoot,
			Allow: func(cert *x509.Certificate) bool {
				return cert.Subject.CommonName == ztsCommonName
			},
		})
	if err != nil {
		return nil, err
	}

	return &params{
		addr: addr,
		handler: util.NewAccessLogHandler(&handler{
			verifier: verifier,
		}, nil),
		tls:           conf,
		shutdownGrace: sg,
		closers:       []io.Closer{closer, watcher},
	}, nil
}

func run(config *rest.Config, program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(config, program, args)
	if err != nil {
		return err
	}
	defer params.Close()

	mux := httptreemux.New()
	mux.POST("/identity", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		params.handler.ServeHTTP(w, r)
	})
	mux.GET("/healthz", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		w.Header().Set("Content-Type", "text/plain;charset=utf8")
		io.WriteString(w, "ok\n")
	})

	server := &http.Server{
		Addr:      params.addr,
		Handler:   mux,
		TLSConfig: params.tls,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.ListenAndServeTLS("", "")
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

	err := run(nil, filepath.Base(os.Args[0]), os.Args[1:], stopChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln("[FATAL]", err)
	}
}
