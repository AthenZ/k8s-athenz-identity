package main

import (
	"crypto/tls"
	"errors"
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

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
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

func getPayload() (*identity.SIAPayload, error) {
	envMap := map[string]string{}
	for _, s := range os.Environ() {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		} else {
			envMap[parts[0]] = ""
		}
	}
	return identity.PayloadFromEnvironment(envMap)
}

type params struct {
	zts          *ztsClient
	instanceFile string
	tokenFile    string
	keyFile      string
	certFile     string
	caCertFile   string
	init         bool
	refresh      time.Duration
	closers      []io.Closer
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
		refreshInterval = envOrDefault("SIA_REFRESH_INTERVAL", "1h")
		ntokenFile      = envOrDefault("SIA_OUT_TOKEN_FILE", "/tokens/ntoken")
		keyFile         = envOrDefault("SIA_OUT_KEY_FILE", "/var/tls/athenz/service.key")
		certFile        = envOrDefault("SIA_OUT_CERT_FILE", "/var/tls/athenz/service.cert")
		caCertFile      = envOrDefault("SIA_OUT_CA_CERT_FILE", "/var/tls/athenz/cacert.pem")
		instanceFile    = envOrDefault("SIA_OUT_INSTANCE_FILE", "/var/tls/athenz/instance.id")
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh, required")
	f.StringVar(&endpoint, "endpoint", endpoint, "ZTS endpoint with /v1 path, required")
	f.StringVar(&authHeader, "auth-header", authHeader, "Athenz auth header name")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "cert refresh interval")
	f.StringVar(&ntokenFile, "ntoken-file", ntokenFile, "ntoken file to write")
	f.StringVar(&certFile, "cert-file", certFile, "cert file to write")
	f.StringVar(&caCertFile, "ca-cert-file", caCertFile, "CA cert file to write")

	f.StringVar(&keyFile, "key-file", keyFile, "key file to write")
	f.StringVar(&instanceFile, "instance-file", instanceFile, "instance ID file to write")

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
		"mode":     mode == "",
		"endpoint": endpoint == "",
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

	payload, err := getPayload()
	if err != nil {
		return nil, err
	}

	client := newZTS(endpoint, payload)
	return &params{
		zts:          client,
		instanceFile: instanceFile,
		tokenFile:    ntokenFile,
		keyFile:      keyFile,
		certFile:     certFile,
		caCertFile:   caCertFile,
		init:         mode == "init",
		refresh:      ri,
	}, nil
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer params.Close()

	writeFiles := func(identity *zts.InstanceIdentity, keyPEM []byte, creds *refreshCredentials) error {
		w := util.NewWriter()
		if err := w.Add(params.certFile, []byte(identity.X509Certificate), 0644); err != nil {
			return err
		}
		if err := w.Add(params.keyFile, keyPEM, 0644); err != nil { // TODO: finalize perms and user
			return err
		}
		if params.caCertFile != "" {
			if err := w.Add(params.caCertFile, []byte(identity.X509CertificateSigner), 0644); err != nil {
				return err
			}
		}
		if err := w.Add(params.instanceFile, []byte(creds.instanceID), 0644); err != nil {
			return err
		}
		if err := w.Add(params.tokenFile, []byte(identity.ServiceToken), 0644); err != nil {
			return err
		}
		return w.Save()
	}

	if params.init {
		id, key, creds, err := params.zts.getIdentity()
		if err != nil {
			return err
		}
		return writeFiles(id, key, creds)
	}

	// recreate refresh credentials state from files written to the filesystem
	instanceBytes, err := ioutil.ReadFile(params.instanceFile)
	if err != nil {
		return err
	}
	certBytes, err := ioutil.ReadFile(params.certFile)
	if err != nil {
		return err
	}
	keyBytes, err := ioutil.ReadFile(params.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return err
	}

	creds := &refreshCredentials{
		instanceID: string(instanceBytes),
		cert:       cert,
	}

	refresh := func() error {
		id, key, newCreds, err := params.zts.refreshIdentity(creds)
		if err != nil {
			return err
		}
		creds = newCreds
		return writeFiles(id, key, creds)
	}

	t := time.NewTicker(params.refresh)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			err := refresh()
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
