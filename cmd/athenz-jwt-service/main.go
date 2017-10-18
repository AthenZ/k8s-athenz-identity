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

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/services/jwt"
	"github.com/yahoo/k8s-athenz-identity/internal/services/keys"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
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

func parseFlags(program string, args []string) (*params, error) {
	var (
		addr          = util.EnvOrDefault("ADDR", ":4443")
		signingKeyDir = util.EnvOrDefault("PRIVATE_KEYS_DIR", "/var/keys/private")
		keyFile       = util.EnvOrDefault("KEY_FILE", "")
		certFile      = util.EnvOrDefault("CERT_FILE", "")
		trustCN       = util.EnvOrDefault("IDENTITY_CN", "")
		shutdownGrace = util.EnvOrDefault("SHUTDOWN_GRACE", "10s")
		tokenExpiry   = util.EnvOrDefault("TOKEN_EXPIRY", "5m")
		secretName    = util.EnvOrDefault("SECRET_PREFIX", "athenz-init-secret")
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)

	f.StringVar(&addr, "listen", addr, "listen address")
	f.StringVar(&signingKeyDir, "sign-key-dir", signingKeyDir, "directory containing private signing keys")
	f.StringVar(&keyFile, "key", keyFile, "path to key")
	f.StringVar(&certFile, "cert", certFile, "path to cert")
	f.StringVar(&trustCN, "identity-cn", trustCN, "common name for identity agent cert")
	f.StringVar(&tokenExpiry, "token-expiry", tokenExpiry, "token expiry for JWTs")
	f.StringVar(&secretName, "secret-name", secretName, "file prefix for private key files")
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

	if err := util.CheckFields("arguments", map[string]bool{
		"key":         keyFile == "",
		"cert":        certFile == "",
		"identity-cn": trustCN == "",
	}); err != nil {
		return nil, err
	}

	privateSource := keys.NewPrivateKeySource(signingKeyDir, secretName)

	cc, err := cp()
	if err != nil {
		return nil, err
	}

	conf, closer, err := cc.ServerTLSConfig(
		config.Credentials{
			KeyFile:  keyFile,
			CertFile: certFile,
		},
		config.VerifyClient{
			Source: config.ServiceRoot,
			Allow: func(c *x509.Certificate) bool {
				return c.Subject.CommonName == trustCN
			},
		})
	if err != nil {
		return nil, err
	}

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
		handler:       util.NewAccessLogHandler(jwt.NewHandler(apiVersionPrefix, ser.IdentityDoc)),
		tls:           conf,
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
