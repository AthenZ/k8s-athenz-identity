// Copyright 2019, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.
package main

import (
	"flag"
	"fmt"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/pkg/identity"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
	"os"
	"path/filepath"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
)

var errEarlyExit = fmt.Errorf("early exit")

// Version gets set by the build script via LDFLAGS
var Version string

const (
	serviceName = "athenz-sia"
)

func getVersion() string {
	if Version == "" {
		return "development version"
	}
	return Version
}

// EnvOrDefault returns the value of the supplied variable or a default string.
func envOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

func parseFlags(program string, args []string) (*identity.IdentityConfig, error) {
	var (
		mode            = ""
		endpoint        = envOrDefault("ENDPOINT", "")
		providerService = envOrDefault("PROVIDER_SERVICE", "")
		dnsSuffix       = envOrDefault("DNS_SUFFIX", "")
		refreshInterval = envOrDefault("REFRESH_INTERVAL", "24h")
		keyFile         = envOrDefault("KEY_FILE", "/var/run/athenz/service.key.pem")
		certFile        = envOrDefault("CERT_FILE", "/var/run/athenz/service.cert.pem")
		caCertFile      = envOrDefault("CA_CERT_FILE", "/var/run/athenz/ca.cert.pem")
		logDir          = envOrDefault("LOG_DIR", "/var/log/"+serviceName)
		logLevel        = envOrDefault("LOG_LEVEL", "INFO")
		saTokenFile     = envOrDefault("SA_TOKEN_FILE", "/var/run/secrets/kubernetes.io/bound-serviceaccount/token")

		//TODO add env var from 4.0 branch
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh, required")
	f.StringVar(&endpoint, "endpoint", endpoint, "Athenz ZTS endpoint")
	f.StringVar(&providerService, "provider-service", providerService, "Identity Provider service")
	f.StringVar(&dnsSuffix, "dns-suffix", dnsSuffix, "DNS Suffix for certs")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "cert refresh interval")
	f.StringVar(&certFile, "out-cert", certFile, "cert file to write")
	f.StringVar(&caCertFile, "out-ca-cert", caCertFile, "CA cert file to write")
	f.StringVar(&keyFile, "out-key", keyFile, "key file to write")
	f.StringVar(&logDir, "log-dir", logDir, "directory to store the server log files")
	f.StringVar(&logLevel, "log-level", logLevel, "logging level")
	f.StringVar(&saTokenFile, "sa-token-file", saTokenFile, "bound sa jwt token file location")

	var showVersion bool
	f.BoolVar(&showVersion, "version", false, "Show version information")

	err := f.Parse(args)
	if err != nil {
		if err == flag.ErrHelp {
			err = errEarlyExit
			return nil, err
		}
		log.InitLogger(filepath.Join(logDir, fmt.Sprintf("%s.%s.log", serviceName, logLevel)), logLevel, true)
		return nil, err
	}

	log.InitLogger(filepath.Join(logDir, fmt.Sprintf("%s.%s.log", serviceName, logLevel)), logLevel, true)
	if showVersion {
		log.Println(getVersion())
		return nil, errEarlyExit
	}

	if !(mode == "init" || mode == "refresh") {
		return nil, fmt.Errorf("invalid mode %q must be one of init or refresh", mode)
	}
	init := mode == "init"

	ri, err := time.ParseDuration(refreshInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh interval %q, %v", refreshInterval, err)
	}

	pollInterval := ri
	if pollInterval > util.DefaultPollInterval {
		pollInterval = util.DefaultPollInterval
	}
	reloader, err := util.NewCertReloader(util.ReloadConfig{
		KeyFile:      keyFile,
		CertFile:     certFile,
		Logger:       log.Debugf,
		PollInterval: pollInterval,
	})
	// During the init flow if X.509 cert(and key) already exists,
	//   - someone is attempting to run init after a pod has been started
	//   - pod sandbox crashed and kubelet runs the init container
	// SIA does not have enough information to differentiate between the two situations.
	// The idea is to delegate the decision to re-issue the X.509 certificate to the identity provider
	// In the case when the podIP changes after a pod sandbox crash, the new pod IP might not have propagated yet
	// to the kube and kubelet APIs. So, we might end up getting an X.509 certificate with the old pod IP.
	// To avoid this, we fail the current run with an error to force SYNC the status on the pod resource and let
	// the subsequent retry for the init container to attempt to get a new certificate from the identity provider.

	if init && err == nil {
		log.Errorf("SIA(init) detected the existence of X.509 cert at %s", certFile)
		cert, err := reloader.GetLatestCertificate()
		if err != nil {
			log.Infof("[X.509 Certificate] Subject: %v, DNS SANs: %v, IPs: %v", cert.Leaf.Subject, cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
		}
		log.Infof("Deleting the existing key and cert...")
		if err := os.Remove(certFile); err != nil {
			log.Errorf("Error deleting %s file: %s", certFile, err.Error())
		}
		if err := os.Remove(keyFile); err != nil {
			log.Errorf("Error deleting %s file: %s", keyFile, err.Error())
		}
		return nil, errors.New("X.509 certificate already exists.")
	}
	if !init && err != nil {
		return nil, errors.Wrap(err, "unable to read key and cert")
	}

	// TODO: create identity NewClient()

	return &identity.IdentityConfig{
		KeyFile:         keyFile,
		CertFile:        certFile,
		CaCertFile:      caCertFile,
		Mode:            mode,
		Init:            init,
		Refresh:         ri,
		Reloader:        reloader,
		SaTokenFile:     saTokenFile,
		Endpoint:        endpoint,
		ProviderService: providerService,
		DNSSuffix:       dnsSuffix,
		Namespace:       os.Getenv("NAMESPACE"),
		Serviceaccount:  os.Getenv("SERVICEACCOUNT"),
		PodIP:           os.Getenv("POD_IP"),
		PodUID:          os.Getenv("POD_UID"),
	}, nil
}

func id2Res(id *zts.InstanceIdentity, keyPEM []byte) *identity.IdentityContext {
	return &identity.IdentityContext{
		KeyPEM:    keyPEM,
		CertPEM:   []byte(id.X509Certificate),
		CACertPem: []byte(id.X509CertificateSigner),
	}
}

func run(idConfig *identity.IdentityConfig, stopChan <-chan struct{}) error {

	writeFiles := func(id *identity.IdentityContext) error {
		w := util.NewWriter()
		log.Debugf("Saving x509 cert[%d bytes] at %s", len(id.CertPEM), idConfig.CertFile)
		if err := w.AddBytes(idConfig.CertFile, 0644, id.CertPEM); err != nil {
			return errors.Wrap(err, "unable to save x509 cert")
		}
		log.Debugf("Saving x509 key[%d bytes] at %s", len(id.KeyPEM), idConfig.KeyFile)
		if err := w.AddBytes(idConfig.KeyFile, 0644, id.KeyPEM); err != nil { // TODO: finalize perms and user
			return errors.Wrap(err, "unable to save x509 key")
		}
		if len(id.CACertPem) != 0 {
			log.Debugf("Saving x509 cacert[%d bytes] at %s", len(id.CACertPem), idConfig.CaCertFile)
			if err := w.AddBytes(idConfig.CaCertFile, 0644, id.CACertPem); err != nil {
				return errors.Wrap(err, "unable to save x509 cacert")
			}
		}
		return w.Save()
	}

	// getExponentialBackoff will return a backoff config with first retry delay of 5s, and backoff retry
	// until params.refresh / 4
	getExponentialBackoff := func() *backoff.ExponentialBackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = idConfig.Refresh / 4
		return b
	}

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to create/refresh cert: %s. Retrying in %s", err.Error(), backoffDelay)
	}

	postRequest := func() error {

		log.Infoln("Attempting to create/refresh x509 cert from identity provider...")

		// TODO: from here
		var id *zts.InstanceIdentity
		var keyPem []byte
		var err error
		if idConfig.Init {
			id, keyPem, err = identity.InitIdentity(*idConfig)
		} else {
			id, keyPem, err = identity.RefreshIdentity(*idConfig)
		}

		if err != nil {
			log.Errorf("Error while creating/refreshing x509 cert: %s", err.Error())
			return err
		}

		idContext := id2Res(id, keyPem)

		log.Infoln("Successfully created/refreshed x509 cert from identity provider")

		x509Cert, err := util.CertificateFromPEMBytes(idContext.CertPEM)
		if err != nil {
			return errors.Wrap(err, "unable to parse x509 cert")
		}
		log.Infof("[New Certificate] Subject: %s, Issuer: %s, NotBefore: %s, NotAfter: %s, SerialNumber: %s",
			x509Cert.Subject, x509Cert.Issuer, x509Cert.NotBefore, x509Cert.NotAfter, x509Cert.SerialNumber)

		return writeFiles(idContext)
	}

	if idConfig.Init {
		return backoff.RetryNotify(postRequest, getExponentialBackoff(), notifyOnErr)
	}

	t := time.NewTicker(idConfig.Refresh)
	defer t.Stop()
	for {
		log.Infof("Refreshing cert[%s] in %s", idConfig.CertFile, idConfig.Refresh)
		select {
		case <-t.C:
			err := backoff.RetryNotify(postRequest, getExponentialBackoff(), notifyOnErr)
			if err != nil {
				log.Errorf("Failed to refresh cert after multiple retries: %s", err.Error())
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
	//signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-ch
		log.Println("Shutting down...")
		close(stopChan)
	}()

	idConfig, err := parseFlags(filepath.Base(os.Args[0]), os.Args[1:])
	if err != nil {
		if err == errEarlyExit {
			return
		}
		log.Fatalln(err)
	}
	if idConfig == nil {
		return
	}

	log.Infoln("Booting up with args", os.Args)
	err = run(idConfig, stopChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln(err)
	}
}
