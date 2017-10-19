package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const (
	keyFileName     = "service.key"
	versionFileName = "service.version"
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
	zts        *ztsClient
	tokenFile  string
	certFile   string
	caCertFile string
	init       bool
	refresh    time.Duration
	closers    []io.Closer
}

func (p *params) Close() error {
	for _, c := range p.closers {
		c.Close()
	}
	return nil
}

func parseFlags(program string, args []string) (*params, error) {
	var (
		mode            = ""
		refreshInterval = util.EnvOrDefault("REFRESH_INTERVAL", "24h")
		namespace       = util.EnvOrDefault("NAMESPACE", "")
		account         = util.EnvOrDefault("ACCOUNT", "")
		identityDir     = util.EnvOrDefault("IDENTITY_DIR", "/var/tls/athenz/private")
		ntokenFile      = util.EnvOrDefault("TOKEN_FILE", "/tokens/ntoken")
		certFile        = util.EnvOrDefault("CERT_FILE", "/var/tls/athenz/public/service.cert")
		caCertFile      = util.EnvOrDefault("CA_CERT_FILE", "/var/tls/athenz/public/ca.cert")
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)

	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh, required")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "cert refresh interval")
	f.StringVar(&ntokenFile, "out-ntoken", ntokenFile, "ntoken file to write")
	f.StringVar(&certFile, "out-cert", certFile, `cert file to write`)
	f.StringVar(&caCertFile, "out-ca-cert", caCertFile, "CA cert file to write (blank to skip the write)")

	f.StringVar(&namespace, "namespace", namespace, "Pod namespace, required")
	f.StringVar(&account, "account", account, "Service account, required")
	f.StringVar(&identityDir, "identity-dir", identityDir, fmt.Sprintf("directory having %q and %q files", keyFileName, versionFileName))
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
		"mode":      mode == "",
		"namespace": namespace == "",
		"account":   account == "",
	}); err != nil {
		return nil, err
	}

	if !(mode == "init" || mode == "refresh") {
		return nil, fmt.Errorf("invalid mode %q must be one of init or refresh", mode)
	}

	cc, err := cp()
	if err != nil {
		return nil, err
	}

	ri, err := time.ParseDuration(refreshInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh interval %q, %v", refreshInterval, err)
	}

	keySource := func() ([]byte, string, error) {
		key, err := ioutil.ReadFile(filepath.Join(identityDir, keyFileName))
		if err != nil {
			return nil, "", err
		}
		ver, err := ioutil.ReadFile(filepath.Join(identityDir, versionFileName))
		if err != nil {
			return nil, "", err
		}
		return key, string(ver), nil
	}

	conf, err := cc.ClientTLSConfig(config.AthenzRoot)
	domain := cc.NamespaceToDomain(namespace)

	spiffeURI, err := cc.SpiffeURI(domain, account)
	if err != nil {
		return nil, errors.Wrap(err, "generate SPIFFE URI")
	}
	client, err := newClient(ztsConfig{
		endpoint:   cc.ZTSEndpoint,
		tls:        conf,
		authHeader: cc.AuthHeader,
		ks:         keySource,
		domain:     domain,
		service:    account,
		opts: util.CSROptions{
			SANs: util.SubjectAlternateNames{
				DNSNames: []string{cc.ServiceURLHost(domain, account)},
				URIs:     []url.URL{*spiffeURI},
			},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create client")
	}
	p := &params{
		init:       mode == "init",
		tokenFile:  ntokenFile,
		certFile:   certFile,
		caCertFile: caCertFile,
		zts:        client,
		refresh:    ri,
	}
	return p, err
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer params.Close()

	saveCerts := func() error {
		token, cert, caCert, err := params.zts.getCertificate()
		if err != nil {
			return errors.Wrap(err, "cert fetch")
		}
		w := util.NewWriter()
		if err := w.AddBytes(params.certFile, 0644, cert); err != nil {
			return err
		}
		if err := w.AddBytes(params.tokenFile, 0644, []byte(token)); err != nil {
			return err
		}
		if params.caCertFile != "" {
			if err := w.AddBytes(params.caCertFile, 0644, caCert); err != nil {
				return err
			}
		}
		return w.Save()
	}

	if params.init {
		return saveCerts()
	}

	t := time.NewTicker(params.refresh)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			err := saveCerts()
			if err != nil { // XXX: maybe shorten interval for refresh on errors?
				log.Println("cert refresh error:", err, ",try again in", params.refresh)
			}
		case <-stopChan:
			return nil
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
