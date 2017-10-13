package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/services/ident"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"golang.org/x/net/context"
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

type artifacts struct {
	tokenFile  string
	keyFile    string
	certFile   string
	caCertFile string
}

type params struct {
	client    ident.Client
	init      bool
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

func parseFlags(program string, args []string) (*params, error) {
	var (
		mode            = ""
		idFile          = util.EnvOrDefault("ID_FILE", "/identity/id")
		endpoint        = util.EnvOrDefault("ENDPOINT", "unix:///identity/connect/agent.sock")
		refreshInterval = util.EnvOrDefault("REFRESH_INTERVAL", "1h")
		ntokenFile      = util.EnvOrDefault("TOKEN_FILE", "/tokens/ntoken")
		keyFile         = util.EnvOrDefault("KEY_FILE", "/tls/service.key")
		certFile        = util.EnvOrDefault("CERT_FILE", "/tls/service.cert")
		caCertFile      = util.EnvOrDefault("CA_CERT_FILE", "/tls/cacert.pem")
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh, required")
	f.StringVar(&idFile, "id-file", idFile, "file containing hashed pod id")
	f.StringVar(&endpoint, "endpoint", endpoint, "TCP or socket endpoint for identity agent")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "cert refresh interval")
	f.StringVar(&ntokenFile, "out-ntoken", ntokenFile, "ntoken file to write")
	f.StringVar(&certFile, "out-cert", certFile, "cert file to write")
	f.StringVar(&caCertFile, "out-ca-cert", caCertFile, "CA cert file to write")
	f.StringVar(&keyFile, "out-key", keyFile, "key file to write")

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

	id, err := ioutil.ReadFile(idFile)
	if err != nil {
		return nil, errors.Wrap(err, "read ID file")
	}
	dialer, err := util.NewDialer(endpoint)
	if err != nil {
		return nil, err
	}
	c := ident.NewClient("http://socket.path/v1", string(id), &http.Client{
		Transport: &http.Transport{
			DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
				return dialer(c)
			},
		},
	})
	return &params{
		client: c,
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

	writeFiles := func(id *ident.Identity) error {
		w := util.NewWriter()
		a := params.artifacts
		if err := w.AddBytes(a.certFile, 0644, id.CertPEM); err != nil {
			return err
		}
		if err := w.AddBytes(a.keyFile, 0644, id.KeyPEM); err != nil { // TODO: finalize perms and user
			return err
		}
		if len(id.CACertPem) != 0 {
			if err := w.AddBytes(a.caCertFile, 0644, id.CACertPem); err != nil {
				return err
			}
		}
		if err := w.AddBytes(a.tokenFile, 0644, []byte(id.NToken)); err != nil {
			return err
		}
		return w.Save()
	}

	if params.init {
		ident, err := params.client.Init()
		if err != nil {
			return errors.Wrap(err, "client.Init")
		}
		return writeFiles(ident)
	}

	keyPEM, err := ioutil.ReadFile(params.artifacts.keyFile)
	if err != nil {
		return errors.Wrap(err, "read key file")
	}
	certPEM, err := ioutil.ReadFile(params.artifacts.certFile)
	if err != nil {
		return errors.Wrap(err, "read cert file")
	}

	refresh := func() error {
		id, err := params.client.Refresh(ident.RefreshRequest{
			KeyPEM:  keyPEM,
			CertPEM: certPEM,
		})
		if err != nil {
			return err
		}
		keyPEM = id.KeyPEM
		certPEM = id.CertPEM
		return writeFiles(id)
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
