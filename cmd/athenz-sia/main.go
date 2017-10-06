package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
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

type artifacts struct {
	tokenFile  string
	keyFile    string
	certFile   string
	caCertFile string
}

type params struct {
	endpoint  string
	ips       []net.IP
	init      bool
	stateFile string
	artifacts artifacts
	refresh   time.Duration
	closers   []io.Closer
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

func getPodIP() (net.IP, error) {
	xfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("unable to get network interfaces, %v", err)
	}
	for _, x := range xfaces {
		if x.Flags&net.FlagLoopback > 0 { // loopback, ignore
			continue
		}
		if x.Flags&net.FlagUp == 0 { // not up
			continue
		}
		addrs, err := x.Addrs()
		if err != nil {
			log.Printf("unable to get addresses for interface %v, %v", x, err)
			continue
		}
		for _, a := range addrs {
			as := a.String()
			ip, _, err := net.ParseCIDR(as)
			if err != nil {
				log.Printf("unable to parse address %s for interface %v, %v", as, x, err)
				continue
			}
			if ip.To4() == nil {
				continue
			}
			return ip, nil
		}
	}
	return nil, fmt.Errorf("unable to get pod IP from any interface")
}

func getSANIPs(override string) ([]net.IP, error) {
	var ip net.IP
	var err error
	if override != "" {
		ip = net.ParseIP(override)
		if ip == nil {
			return nil, fmt.Errorf("unable to parse override IP %q", override)
		}
	} else {
		ip, err = getPodIP()
		if err != nil {
			return nil, err
		}
	}
	return []net.IP{ip}, nil
}

func parseFlags(program string, args []string) (*params, error) {
	var (
		mode            = ""
		endpoint        = envOrDefault("SIA_ZTS_ENDPOINT", "")
		authHeader      = envOrDefault("SIA_AUTH_HEADER", "Athenz-Principal-Auth")
		refreshInterval = envOrDefault("SIA_REFRESH_INTERVAL", "1h")
		podIP           = envOrDefault("SIA_POD_IP", "")
		stateFile       = envOrDefault("SIA_STATE_FILE", "/tmp/sia-state.json")
		ntokenFile      = envOrDefault("SIA_OUT_TOKEN_FILE", "/tokens/ntoken")
		keyFile         = envOrDefault("SIA_OUT_KEY_FILE", "/var/tls/athenz/service.key")
		certFile        = envOrDefault("SIA_OUT_CERT_FILE", "/var/tls/athenz/service.cert")
		caCertFile      = envOrDefault("SIA_OUT_CA_CERT_FILE", "/var/tls/athenz/cacert.pem")
		instanceFile    = envOrDefault("SIA_OUT_INSTANCE_FILE", "/var/tls/athenz/instance.id")
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh, required")
	f.StringVar(&endpoint, "endpoint", endpoint, "ZTS endpoint with /v1 path, required")
	f.StringVar(&podIP, "pod-ip", podIP, "use pod IP passed in for certificate, default is current IP")
	f.StringVar(&authHeader, "auth-header", authHeader, "Athenz auth header name")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "cert refresh interval")
	f.StringVar(&stateFile, "state-file", stateFile, "state file to write for refresh context")
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

	ips, err := getSANIPs(podIP)
	if err != nil {
		return nil, err
	}

	return &params{
		endpoint:  endpoint,
		ips:       ips,
		stateFile: stateFile,
		artifacts: artifacts{
			tokenFile:  ntokenFile,
			keyFile:    keyFile,
			certFile:   certFile,
			caCertFile: caCertFile,
		},
		init:    mode == "init",
		refresh: ri,
	}, nil
}

func run(program string, args []string, stopChan <-chan struct{}) error {
	params, err := parseFlags(program, args)
	if err != nil {
		return err
	}
	defer params.Close()

	writeFiles := func(identity *zts.InstanceIdentity, keyPEM []byte, cert *tls.Certificate) error {
		w := util.NewWriter()
		a := params.artifacts
		if err := w.Add(a.certFile, []byte(identity.X509Certificate), 0644); err != nil {
			return err
		}
		if err := w.Add(a.keyFile, keyPEM, 0644); err != nil { // TODO: finalize perms and user
			return err
		}
		if a.caCertFile != "" {
			if err := w.Add(a.caCertFile, []byte(identity.X509CertificateSigner), 0644); err != nil {
				return err
			}
		}
		if err := w.Add(a.tokenFile, []byte(identity.ServiceToken), 0644); err != nil {
			return err
		}
		return w.Save()
	}

	writeStateFile := func(c identity.Context) error {
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		return ioutil.WriteFile(params.stateFile, b, 0644)
	}

	readStateFile := func() (identity.Context, error) {
		var c identity.Context
		b, err := ioutil.ReadFile(params.stateFile)
		if err != nil {
			return c, err
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return c, err
		}
		if err := c.AssertValid(); err != nil {
			return c, fmt.Errorf("bad context in state file, %v", err)
		}
		if c.InstanceID == "" {
			return c, fmt.Errorf("context did not have an instance ID")
		}
		return c, nil
	}

	if params.init {
		payload, err := getPayload()
		if err != nil {
			return err
		}
		z := newZTS(params.endpoint, payload.Context, params.ips)
		id, key, cert, err := z.getIdentity(payload.IdentityDoc)
		if err != nil {
			return err
		}
		payload.Context.InstanceID = string(id.InstanceId)
		if err := writeStateFile(payload.Context); err != nil {
			return err
		}
		return writeFiles(id, key, cert)
	}

	context, err := readStateFile()
	if err != nil {
		return fmt.Errorf("readStateFile: %v", err)
	}
	certBytes, err := ioutil.ReadFile(params.artifacts.certFile)
	if err != nil {
		return err
	}
	keyBytes, err := ioutil.ReadFile(params.artifacts.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return err
	}

	z := newZTS(params.endpoint, context, params.ips)
	refresh := func() error {
		id, key, newCert, err := z.refreshIdentity(&cert)
		if err != nil {
			return err
		}
		cert = *newCert
		return writeFiles(id, key, newCert)
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
