package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
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

func envOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

func parseFlags(program string, args []string) (*params, error) {
	var (
		mode            = ""
		endpoint        = envOrDefault("SIA_ZTS_ENDPOINT", "")
		authHeader      = envOrDefault("SIA_AUTH_HEADER", "Athenz-Principal-Auth")
		refreshInterval = envOrDefault("SIA_REFRESH_INTERVAL", "24h")
		domain          = envOrDefault("ATHENZ_DOMAIN", "")
		service         = envOrDefault("ATHENZ_SERVICE", "")
		dnsSuffix       = envOrDefault("SIA_ATHENZ_DNS_SUFFIX", "")
		identityDir     = envOrDefault("SIA_IN_IDENTITY_DIR", "/var/tls/athenz/private")
		ntokenFile      = envOrDefault("SIA_OUT_TOKEN_FILE", "/tokens/ntoken")
		certFile        = envOrDefault("SIA_OUT_CERT_FILE", "/var/tls/athenz/public/service.cert")
		caCertFile      = envOrDefault("SIA_OUT_CA_CERT_FILE", "")
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)

	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh, required")
	f.StringVar(&endpoint, "endpoint", endpoint, "ZTS endpoint with /v1 path, required")
	f.StringVar(&authHeader, "auth-header", authHeader, "Athenz auth header name")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "cert refresh interval")
	f.StringVar(&ntokenFile, "ntoken-file", ntokenFile, "ntoken file to write")
	f.StringVar(&certFile, "cert-file", certFile, `cert file to write`)
	f.StringVar(&caCertFile, "ca-cert", caCertFile, "CA cert file to write (blank to skip the write)")

	f.StringVar(&domain, "domain", domain, "Athenz domain, required")
	f.StringVar(&service, "service", service, "Athenz service, required")
	f.StringVar(&dnsSuffix, "dns-suffix", dnsSuffix, "DNS suffix for CSR SAN name, required")
	f.StringVar(&identityDir, "identity-dir", identityDir, fmt.Sprintf("directory having %q and %q files", keyFileName, versionFileName))

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

	if err := util.CheckFields("arguments", map[string]bool{
		"mode":       mode == "",
		"endpoint":   endpoint == "",
		"domain":     domain == "",
		"service":    service == "",
		"dns-suffix": dnsSuffix == "",
	}); err != nil {
		return nil, err
	}

	if !(mode == "init" || mode == "refresh") {
		return nil, fmt.Errorf("invalid mode %q must be one of init or refresh", mode)
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

	client, err := newClient(ztsConfig{
		endpoint:   endpoint,
		authHeader: authHeader,
		ks:         keySource,
		domain:     domain,
		service:    service,
		opts: util.CSROptions{
			DNSNames: []string{fmt.Sprintf("%s.%s.%s", service, strings.Replace(domain, ".", "-", -1), dnsSuffix)},
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
		if err := w.Add(params.certFile, cert, 0644); err != nil {
			return err
		}
		if err := w.Add(params.tokenFile, []byte(token), 0644); err != nil {
			return err
		}
		if params.caCertFile != "" {
			if err := w.Add(params.caCertFile, caCert, 0644); err != nil {
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
