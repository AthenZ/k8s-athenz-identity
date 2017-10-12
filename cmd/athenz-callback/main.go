package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dimfeld/httptreemux"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/services"
	"github.com/yahoo/k8s-athenz-identity/internal/services/config"
	"github.com/yahoo/k8s-athenz-identity/internal/services/keys"
	"github.com/yahoo/k8s-athenz-identity/internal/tlsutil"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func envOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

func parseFlags(clusterConfig *rest.Config, program string, args []string) (*params, error) {
	var (
		addr          = envOrDefault("ADDR", ":4443")
		adminDomain   = envOrDefault("ADMIN_DOMAIN", "k8s.admin")
		keyFile       = envOrDefault("KEY_FILE", "/var/tls/athenz/private/service.key")
		certFile      = envOrDefault("CERT_FILE", "/var/tls/athenz/public/service.cert")
		caCertFile    = envOrDefault("CA_CERT_FILE", "")
		publicKeyDir  = envOrDefault("PUBLIC_KEYS_DIR", "/var/keys/public")
		shutdownGrace = envOrDefault("SHUTDOWN_GRACE", "10s")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&addr, "listen", addr, "[<ip>]:<port> to listen on")
	f.StringVar(&keyFile, "key", keyFile, "path to key file")
	f.StringVar(&certFile, "cert", certFile, "path to cert file")
	f.StringVar(&caCertFile, "ca-cert", caCertFile, "path to CA cert")
	f.StringVar(&publicKeyDir, "sign-pub-dir", publicKeyDir, "directory containing public signing keys")
	f.StringVar(&adminDomain, "admin-domain", adminDomain, "athenz admin domain for cluster")
	f.StringVar(&shutdownGrace, "shutdown-grace", shutdownGrace, "grace period for connections to drain at shutdown")

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

	publicSource := keys.NewPublicKeySource(publicKeyDir, services.AthensInitSecret)
	mapper := identity.NewMapper(config.ClusterConfiguration{}, nil) // TODO: FIX ARGUMENTS
	verifier, err := identity.NewVerifier(identity.VerifierConfig{
		AttributeProvider: func(podID string) (*identity.PodSubject, error) {
			parts := strings.SplitN(podID, "/", 2)
			if len(parts) < 2 {
				return nil, fmt.Errorf("invalid pod id %q, want namespace/name", podID)
			}
			pod, err := cs.CoreV1().Pods(parts[0]).Get(parts[1], meta_v1.GetOptions{})
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

	config, closer, err := tlsutil.ServerConfig(tlsutil.Config{
		KeyFile:    keyFile,
		CertFile:   certFile,
		CACertFile: caCertFile,
	})
	if err != nil {
		return nil, err
	}

	return &params{
		addr: addr,
		handler: &handler{
			verifier: verifier,
		},
		tls:           config,
		shutdownGrace: sg,
		closers:       []io.Closer{closer},
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
