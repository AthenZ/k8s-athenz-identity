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
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/services"
	"github.com/yahoo/k8s-athenz-identity/internal/services/config"
	"github.com/yahoo/k8s-athenz-identity/internal/services/jwt"
	"github.com/yahoo/k8s-athenz-identity/internal/services/keys"
	"github.com/yahoo/k8s-athenz-identity/internal/tlsutil"
)

var errEarlyExit = fmt.Errorf("early exit")

const apiVersionPrefix = "/v1"

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
	tls           *tls.Config
	closers       []io.Closer
	shutdownGrace time.Duration
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
		signingKeyDir = envOrDefault("PRIVATE_KEYS_DIR", "/var/keys/private")
		keyFile       = envOrDefault("KEY_FILE", "/var/tls/athenz/private/service.key")
		certFile      = envOrDefault("CERT_FILE", "/var/tls/athenz/public/service.cert")
		trustService  = envOrDefault("IDENTITY_SERVICE", "athenz-identity-agent.k8s-admin.svc.cluster.local")
		shutdownGrace = envOrDefault("SHUTDOWN_GRACE", "10s")
		tokenExpiry   = envOrDefault("TOKEN_EXPIRY", "5m")
		configURL     = envOrDefault("CONFIG_URL", "http://athenz-config.kube-system/v1/cluster")
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)

	f.StringVar(&addr, "listen", addr, "listen address")
	f.StringVar(&signingKeyDir, "sign-key-dir", signingKeyDir, "directory containing private signing keys")
	f.StringVar(&keyFile, "key", keyFile, "path to key")
	f.StringVar(&certFile, "cert", certFile, "path to cert")
	f.StringVar(&trustService, "identity-service", trustService, "service allowed to mint JWTs")
	f.StringVar(&tokenExpiry, "token-expiry", tokenExpiry, "token expiry for JWTs")
	f.StringVar(&configURL, "config", configURL, "cluster config URL or local file path")
	f.StringVar(&shutdownGrace, "shutdown-grace", shutdownGrace, "grace period for connections to drain at shutdown")

	var showVersion bool
	f.BoolVar(&showVersion, "version", false, "Show version information")

	err := f.Parse(args)
	if err != nil {
		return nil, err
	}

	if showVersion {
		fmt.Println(getVersion())
		return nil, errEarlyExit
	}

	privateSource := keys.NewPrivateKeySource(signingKeyDir, services.AthensInitSecret)

	cc, err := config.Load(configURL)
	if err != nil {
		return nil, err
	}
	servicePool, err := cc.TrustRoot(config.ServiceRoot)
	if err != nil {
		return nil, err
	}

	config, closer, err := tlsutil.ServerConfig(tlsutil.Config{
		KeyFile:  keyFile,
		CertFile: certFile,
	})
	if err != nil {
		return nil, err
	}
	config.ClientCAs = servicePool
	// TODO: make thios stronger and only allow the identity agent to connect

	sg, err := time.ParseDuration(shutdownGrace)
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown grace %q, %v", shutdownGrace, err)
	}
	te, err := time.ParseDuration(tokenExpiry)
	if err != nil {
		return nil, fmt.Errorf("invalid token expiry %q, %v", tokenExpiry, err)
	}

	sc := identity.SerializerConfig{
		TokenExpiry: te,
		KeyProvider: privateSource.SigningKey,
	}
	ser, err := identity.NewSerializer(sc)
	if err != nil {
		return nil, errors.Wrap(err, "serializer creation")
	}
	p := &params{
		addr:          addr,
		handler:       jwt.NewHandler(apiVersionPrefix, ser.IdentityDoc),
		tls:           config,
		closers:       []io.Closer{closer},
		shutdownGrace: sg,
	}
	return p, err
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer params.Close()
	mux := http.NewServeMux()
	mux.Handle(apiVersionPrefix+"/", params.handler)
	mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain;charset=utf8")
		io.WriteString(w, "ok\n")
	}))

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
	err := run(filepath.Base(os.Args[0]), os.Args[1:], stopChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln("[FATAL]", err)
	}
}
