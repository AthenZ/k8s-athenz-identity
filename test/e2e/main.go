// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
)

type httpConfig struct {
	key        string
	cert       string
	caCert     string
	serverURL  string
	commonName string
}

// getVerifier iterates through the certificate chain and runs the verification function check
// passed in.
func getVerifier(allowFn func(*x509.Certificate) bool) func([][]byte, [][]*x509.Certificate) error {
	if allowFn == nil {
		return nil
	}
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, certs := range verifiedChains {
			leaf := certs[0]
			if allowFn(leaf) {
				return nil
			}
		}
		return fmt.Errorf("client identity verification failed")
	}
}

// getHTTPClient will create an http client with a tls config
func (h *httpConfig) getHTTPClient() (*http.Client, error) {
	reloader, err := util.NewCertReloader(util.ReloadConfig{
		KeyFile:  h.key,
		CertFile: h.cert,
	})

	b, err := ioutil.ReadFile(h.caCert)
	if err != nil {
		log.Fatalln("Failed reading ca cert file")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b)) {
		log.Fatalln("Unable to append ca certificates from pem")
	}

	clientTlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: h.serverURL,
	}
	clientTlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return reloader.GetLatestCertificate()
	}
	clientTlsConfig.VerifyPeerCertificate = getVerifier(func(cert *x509.Certificate) bool {
		return cert.Subject.CommonName == h.commonName
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   clientTlsConfig,
			DisableKeepAlives: true,
		},
	}
	return client, nil
}

// get will curl the provided url and return the response
func get(client *http.Client, serverURL, path string) (*http.Response, error) {
	resp, err := client.Get("https://" + serverURL + ":4443" + path)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Debugln(string(b))

	return resp, nil
}

// getCertificate finds the certificate matching the common name specified
func getCertificate(resp *http.Response, commonName string) (*x509.Certificate, error) {
	for _, cert := range resp.TLS.PeerCertificates {
		if cert.Subject.CommonName == commonName {
			return cert, nil
		}
	}
	return nil, errors.New("cert not found matching common name")
}

// validateCertRefresh will validate the certificate was refreshed after a util.DefaultPollInterval + time.Minute waiting period
func validateCertRefresh(client *http.Client, serverURL, path, commonName string, wg *sync.WaitGroup) {
	resp, err := get(client, serverURL, path)
	if err != nil {
		log.Panicln("Error accessing server:", err.Error())
	}

	cert, err := getCertificate(resp, commonName)
	if err != nil {
		log.Panicln("Error getting certificate:", err.Error())
	}

	time.Sleep(util.DefaultPollInterval + time.Minute)

	resp, err = get(client, serverURL, path)
	if err != nil {
		log.Panicln("Error accessing server:", err.Error())
	}

	refreshedCert, err := getCertificate(resp, commonName)
	if err != nil {
		log.Panicln("Error getting certificate:", err.Error())
	}

	if refreshedCert.NotAfter.Before(cert.NotAfter) || refreshedCert.NotBefore.Before(cert.NotBefore) {
		log.Panicf("Certificate was not refreshed in %s.\n", util.DefaultPollInterval+time.Minute)
	}

	if reflect.DeepEqual(cert.SerialNumber, refreshedCert.SerialNumber) {
		log.Panicf("Certificate serial numbers are the same: %+v.", cert.SerialNumber)
	}

	sort.Strings(cert.DNSNames)
	sort.Strings(refreshedCert.DNSNames)
	if !reflect.DeepEqual(cert.DNSNames, refreshedCert.DNSNames) {
		log.Panicf("SANs are not equal, expected: %+v, got: %+v", cert.DNSNames, refreshedCert.DNSNames)
	}

	wg.Done()
}

type test struct {
	name               string
	client             *http.Client
	serverURL          string
	path               string
	expectedStatusCode int
}

func (t *test) runTest() error {
	log.Println("Running", t.name)
	resp, err := get(t.client, t.serverURL, t.path)
	if err != nil {
		return errors.New("Error accessing server: " + err.Error())
	}

	if resp.StatusCode != t.expectedStatusCode {
		errMsg := "Non expected status code: " + strconv.Itoa(resp.StatusCode) + " expected: " + strconv.Itoa(t.expectedStatusCode)
		return backoff.Permanent(errors.New(errMsg))
	}

	return nil
}

func main() {
	program := filepath.Base(os.Args[0])
	args := os.Args[1:]

	f := flag.NewFlagSet(program, flag.ContinueOnError)

	key := f.String("key", "/tokens/key", "Private key.")
	cert := f.String("cert", "/tokens/cert", "Cert.")
	caCert := f.String("ca-cert", "", "Athenz CA cert to use.")
	namespace := f.String("namespace", "kube-test", "Namespace test application is running in.")
	appName := f.String("app-name", "athenz-identity-test-app", "Test application name.")
	adminDomain := f.String("admin-domain", "", "Admin domain")
	clusterDNSSuffix := f.String("cluster-dns-suffix", "", "Cluster DNS suffix")

	err := f.Parse(args)
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		log.InitLogger("/var/log/identityd-e2e-test/identityd-e2e-test.log", "debug", true)
		log.Fatalln("Error parsing arguments:", err.Error())
	}

	log.InitLogger("/var/log/identityd-e2e-test/identityd-e2e-test.log", "debug", true)

	frontend := *appName + "-frontend"
	backend := *appName + "-backend"
	adminDomainK8s := strings.Replace(*adminDomain, ".", "-", -1)
	frontendServerURL := frontend + "." + adminDomainK8s + "-" + *namespace + "." + *clusterDNSSuffix
	backendServerURL := backend + "." + adminDomainK8s + "-" + *namespace + "." + *clusterDNSSuffix
	frontendCommonName := *adminDomain + "." + *namespace + "." + frontend
	backendCommonName := *adminDomain + "." + *namespace + "." + backend

	log.Println("Running tests for", *appName, "application in namespace", *namespace)
	log.Println("Using frontend server url", frontendServerURL, "with frontend common name", frontendCommonName)
	log.Println("Using backend server url", backendServerURL, "with backend common name", backendCommonName)

	fConfig := &httpConfig{*key, *cert, *caCert, frontendServerURL, frontendCommonName}
	frontendClient, err := fConfig.getHTTPClient()
	if err != nil {
		log.Panicln("Error creating frontend http client:", err.Error())
	}

	bConfig := &httpConfig{*key, *cert, *caCert, backendServerURL, backendCommonName}
	backendClient, err := bConfig.getHTTPClient()
	if err != nil {
		log.Panicln("Error creating backend http client:", err.Error())
	}

	// getExponentialBackoff will return a backoff config with first retry delay of 5s and backoff retry until 10m
	getExponentialBackoff := func() *backoff.ExponentialBackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = time.Minute * 20
		return b
	}

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to run http get: %s. Retrying in %s", err.Error(), backoffDelay)
	}

	tests := []test{
		{"/status.html on frontend", frontendClient, frontendServerURL, "/status.html", http.StatusOK},
		{"/status.html on backend", backendClient, backendServerURL, "/status.html", http.StatusOK},
		{"/athenzClientOnly on frontend", frontendClient, frontendServerURL, "/athenzClientOnly", http.StatusOK},
		{"/athenzClientOnly on backend", backendClient, backendServerURL, "/athenzClientOnly", http.StatusOK},
		{"/frontend on frontend", frontendClient, frontendServerURL, "/frontend", http.StatusOK},
		{"/backend on backend", backendClient, backendServerURL, "/backend", http.StatusForbidden},
	}

	for _, test := range tests {
		err := backoff.RetryNotify(test.runTest, getExponentialBackoff(), notifyOnErr)
		if err != nil {
			log.Panicln(err.Error())
		}
	}

	log.Println("Running cert refresh test.")
	var wg sync.WaitGroup
	wg.Add(1)
	go validateCertRefresh(frontendClient, frontendServerURL, "/athenzClientOnly", frontendCommonName, &wg)
	wg.Add(1)
	go validateCertRefresh(backendClient, backendServerURL, "/athenzClientOnly", backendCommonName, &wg)
	wg.Wait()

	log.Println("Successfully ran all test cases.")
}
