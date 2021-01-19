// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/pkg/identity"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
)

const serviceName = "athenz-sia"

var errEarlyExit = fmt.Errorf("early exit")

// envOrDefault returns the value of the supplied variable or a default string.
func envOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

// parseFlags parses ENV and cmd line args and returns an IdentityConfig object
func parseFlags(program string, args []string) (*identity.IdentityConfig, error) {
	var (
		mode            = envOrDefault("MODE", "init")
		endpoint        = envOrDefault("ENDPOINT", "")
		providerService = envOrDefault("PROVIDER_SERVICE", "")
		dnsSuffix       = envOrDefault("DNS_SUFFIX", "")
		refreshInterval = envOrDefault("REFRESH_INTERVAL", "24h")
		keyFile         = envOrDefault("KEY_FILE", "/var/run/athenz/service.key.pem")
		certFile        = envOrDefault("CERT_FILE", "/var/run/athenz/service.cert.pem")
		caCertFile      = envOrDefault("CA_CERT_FILE", "/var/run/athenz/ca.cert.pem")
		logDir          = envOrDefault("LOG_DIR", "/var/log/athenz-sia")
		logLevel        = envOrDefault("LOG_LEVEL", "INFO")
		saTokenFile     = envOrDefault("SA_TOKEN_FILE", "/var/run/secrets/kubernetes.io/bound-serviceaccount/token")
		serverCACert    = envOrDefault("SERVER_CA_CERT", "")

		namespace      = envOrDefault("NAMESPACE", "")
		serviceAccount = envOrDefault("SERVICEACCOUNT", "")
		podIP          = envOrDefault("POD_IP", "")
		podUID         = envOrDefault("POD_UID", "")
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
	f.StringVar(&serverCACert, "server-ca-cert", serverCACert, "path to CA cert file to verify ZTS server certs")

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

	return &identity.IdentityConfig{
		Init:            init,
		KeyFile:         keyFile,
		CertFile:        certFile,
		CaCertFile:      caCertFile,
		Refresh:         ri,
		Reloader:        reloader,
		ServerCACert:    serverCACert,
		SaTokenFile:     saTokenFile,
		Endpoint:        endpoint,
		ProviderService: providerService,
		DNSSuffix:       dnsSuffix,
		Namespace:       namespace,
		ServiceAccount:  serviceAccount,
		PodIP:           podIP,
		PodUID:          podUID,
	}, nil
}

func run(idConfig *identity.IdentityConfig, stopChan <-chan struct{}) error {

	writeFiles := func(id *zts.InstanceIdentity, keyPEM []byte) error {
		certPEM := []byte(id.X509Certificate)
		caCertPEM := []byte(id.X509CertificateSigner)
		x509Cert, err := util.CertificateFromPEMBytes(certPEM)
		if err != nil {
			return errors.Wrap(err, "unable to parse x509 cert")
		}
		log.Infof("[New Certificate] Subject: %s, Issuer: %s, NotBefore: %s, NotAfter: %s, SerialNumber: %s",
			x509Cert.Subject, x509Cert.Issuer, x509Cert.NotBefore, x509Cert.NotAfter, x509Cert.SerialNumber)
		w := util.NewWriter()
		log.Debugf("Saving x509 cert[%d bytes] at %s", len(certPEM), idConfig.CertFile)
		if err := w.AddBytes(idConfig.CertFile, 0644, certPEM); err != nil {
			return errors.Wrap(err, "unable to save x509 cert")
		}
		log.Debugf("Saving x509 key[%d bytes] at %s", len(keyPEM), idConfig.KeyFile)
		if err := w.AddBytes(idConfig.KeyFile, 0644, keyPEM); err != nil { // TODO: finalize perms and user
			return errors.Wrap(err, "unable to save x509 key")
		}
		if len(caCertPEM) != 0 {
			log.Debugf("Saving x509 cacert[%d bytes] at %s", len(caCertPEM), idConfig.CaCertFile)
			if err := w.AddBytes(idConfig.CaCertFile, 0644, caCertPEM); err != nil {
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

	handler, err := identity.InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Error while initializing handler: %s", err.Error())
		return err
	}

	postRequest := func() error {
		log.Infoln("Attempting to create/refresh x509 cert from identity provider...")

		id, keyPem, err := handler.GetX509Cert()
		if err != nil {
			log.Errorf("Error while creating/refreshing x509 cert: %s", err.Error())
			return err
		}

		log.Infoln("Successfully created/refreshed x509 cert from identity provider")
		return writeFiles(id, keyPem)
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
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
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

	log.Infoln("Booting up with args", os.Args)
	err = run(idConfig, stopChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln(err)
	}
}
