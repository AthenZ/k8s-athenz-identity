package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"syscall"
	"time"

	"github.com/dimfeld/httptreemux"
	"github.com/yahoo/k8s-athenz-identity/internal/common"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/keys"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

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
		addr          = envOrDefault("ATHENZ_CB_LISTEN_ADDR", ":4443")
		keyFile       = envOrDefault("ATHENZ_CB_KEY_FILE", "/var/tls/athenz/private/service.key")
		certFile      = envOrDefault("ATHENZ_CB_CERT_FILE", "/var/tls/athenz/public/service.cert")
		caCertFile    = envOrDefault("ATHENZ_CB_CA_CERT_FILE", "")
		publicKeyDir  = envOrDefault("ATHENZ_CB_PUBLIC_KEYS_DIR", "/var/keys/public")
		shutdownGrace = envOrDefault("ATHENS_CB_SHUTDOWN_GRACE", "10s")
	)

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&addr, "listen", addr, "[<ip>]:<port> to listen on")
	f.StringVar(&keyFile, "tls-key", keyFile, "path to TLS key")
	f.StringVar(&certFile, "tls-cert", certFile, "path to TLS cert")
	f.StringVar(&caCertFile, "ca-cert", caCertFile, "path to CA cert")
	f.StringVar(&publicKeyDir, "sign-pub-dir", publicKeyDir, "directory containing public signing keys")
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

	publicSource := keys.NewPublicKeySource(publicKeyDir, common.AthensInitSecret)
	verifier, err := identity.NewVerifier(identity.VerifierConfig{
		AttributeProvider: func(podID string) (*identity.PodAttributes, error) {
			parts := strings.SplitN(podID, "/", 2)
			if len(parts) < 2 {
				return nil, fmt.Errorf("invalid pod id %q, want namespace/name", podID)
			}
			pod, err := cs.CoreV1().Pods(parts[0]).Get(parts[1], meta_v1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return common.Pod2Attributes(pod)
		},
		PublicKeyProvider: publicSource.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	reloader, err := util.NewCertReloader(util.ReloadConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		return nil, err
	}

	var pool *x509.CertPool
	if caCertFile != "" {
		pem, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("CA cert %s, %v", caCertFile, err)
		}
		pool = x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(pem)
		if !ok {
			return nil, fmt.Errorf("unable to load any CA certs from %s", caCertFile)
		}
	}

	return &params{
		addr: addr,
		handler: &handler{
			verifier: verifier,
		},
		tls: &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return reloader.GetLatestCertificate()
			},
			ClientCAs: pool,
		},
		shutdownGrace: sg,
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
