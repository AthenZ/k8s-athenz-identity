// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
)

type certInfo struct {
	CommonName   string    `json:"commonName"`
	DNSNames     []string  `json:"dnsNames"`
	DNSIPs       []string  `json:"ips"`
	URIs         []string  `json:"uris"`
	SerialNumber *big.Int  `json:"serialNumber"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	Issuer       pkix.Name `json:"issuer"`
}

type frontendMgr struct {
	client     *http.Client
	backendURL string
	domain     string
}

type backendMgr struct {
	reloader           *util.CertReloader
	frontendCommonName string
}

func statusHandler(rw http.ResponseWriter, _ *http.Request) {
	io.WriteString(rw, "OK")
}

// athenzClientOnlyHandler verifies that the client presents at least one peer certificate. The response returns the
// first peer certificate found.
func athenzClientOnlyHandler(rw http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		log.Errorln("No athenz client certificate provided")
		http.Error(rw, "No athenz client certificate provided", http.StatusForbidden)
		return
	}

	if len(req.TLS.PeerCertificates) > 1 {
		log.Warningln("More than one peer certificate detected. Only the first one will be returned.")
	}

	for _, peerCertificate := range req.TLS.PeerCertificates {
		log.Println("Serving request for:", peerCertificate.Subject.CommonName)
		b, err := getCertInfo(peerCertificate)
		if err != nil {
			log.Errorln("Error converting to certInfo object:", err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.Write(b)
		return
	}

	log.Errorln("Couldn't parse peer certificates")
	http.Error(rw, "Couldn't parse peer certificates", http.StatusInternalServerError)
}

// getCertInfo parses the x509 cert and creates a certInfo object.
func getCertInfo(cert *x509.Certificate) ([]byte, error) {
	var info *certInfo

	info = &certInfo{
		CommonName:   cert.Subject.CommonName,
		DNSNames:     cert.DNSNames,
		SerialNumber: cert.SerialNumber,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Issuer:       cert.Issuer,
	}
	for _, ip := range cert.IPAddresses {
		info.DNSIPs = append(info.DNSIPs, ip.String())
	}
	sans, err := util.UnmarshalSANs(cert.Extensions)
	if err != nil {
		return nil, err
	}

	for _, u := range sans.URIs {
		info.URIs = append(info.URIs, u.String())
	}

	return json.MarshalIndent(info, "", "  ")
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

// backendHandler will respond with the servers certificate only for requests coming from the /frontend path. The
// incoming requests certificate is verified against the expected frontends common name.
func (bMgr *backendMgr) backendHandler(rw http.ResponseWriter, req *http.Request) {
	verifyPeerCertificate := getVerifier(func(cert *x509.Certificate) bool {
		return cert.Subject.CommonName == bMgr.frontendCommonName
	})

	err := verifyPeerCertificate(nil, req.TLS.VerifiedChains)
	if err != nil {
		log.Errorln("Client certificate does not have expected common name:", bMgr.frontendCommonName)
		http.Error(rw, "Client certificate does not have expected common name: "+bMgr.frontendCommonName, http.StatusForbidden)
		return
	}

	cert, err := bMgr.reloader.GetLatestCertificate()
	if err != nil {
		log.Errorln("Error getting the latest certificate of the server:", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	leafBytes := cert.Certificate[0]
	c, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		log.Errorln("Error parsing certificate:", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := getCertInfo(c)
	if err != nil {
		log.Errorln("Error converting to certInfo object:", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(b)
}

// frontendHandler will make a call to the /backend path and return the response.
func (fMgr *frontendMgr) frontendHandler(rw http.ResponseWriter, req *http.Request) {
	resp, err := fMgr.client.Get(fMgr.backendURL)
	if err != nil {
		log.Errorln("Error accessing the backend server:", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorln("Non 200 status code: " + strconv.Itoa(resp.StatusCode))
		http.Error(rw, "Non 200 status code: "+strconv.Itoa(resp.StatusCode), resp.StatusCode)
		return
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorln("Failed to read response body:", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Debugln(string(b))
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(b)
}

func main() {
	program := filepath.Base(os.Args[0])
	args := os.Args[1:]

	f := flag.NewFlagSet(program, flag.ContinueOnError)
	frontend := f.Bool("frontend", false, "Run only the frontend application.")
	backend := f.Bool("backend", false, "Run only the backend application.")
	key := f.String("key", "/var/run/athenz/service.key.pem", "Service private key.")
	cert := f.String("cert", "/var/run/athenz/service.cert.pem", "Service cert.")
	caCert := f.String("ca-cert", "/var/run/athenz/ca.cert.pem", "CA cert.")
	backendURL := f.String("backend-url", "", "Backend URL of the backend application the frontend will call.")
	frontendCommonName := f.String("frontend-common-name", "", "Frontend common name to verify against.")
	backendCommonName := f.String("backend-common-name", "", "Backend common name to verify against.")

	err := f.Parse(args)
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		log.InitLogger("/var/log/athenz-identity-test-app/athenz-identity-test-app.log", "debug", true)
		log.Fatalln("Error parsing arguments:", err.Error())
	}

	log.InitLogger("/var/log/athenz-identity-test-app/athenz-identity-test-app.log", "debug", true)
	if !*frontend && !*backend {
		*frontend = true
		*backend = true
	}

	if *frontend && *backendURL == "" && *backendCommonName == "" {
		log.Fatalln("backendURL and backendCommonName argument must be set.")
	}

	if *backend && *frontendCommonName == "" {
		log.Fatalln("frontendCommonName argument must be set.")
	}

	reloader, err := util.NewCertReloader(util.ReloadConfig{
		KeyFile:  *key,
		CertFile: *cert,
	})

	b, err := ioutil.ReadFile(*caCert)
	if err != nil {
		log.Fatalln("Failed reading ca cert file")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b)) {
		log.Fatalln("Unable to append ca certificates from pem")
	}

	serverTlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}
	serverTlsConfig.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return reloader.GetLatestCertificate()
	}
	serverTlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return reloader.GetLatestCertificate()
	}

	server := &http.Server{
		Addr:      ":4443",
		TLSConfig: serverTlsConfig,
	}

	http.HandleFunc("/status.html", statusHandler)
	http.HandleFunc("/athenzClientOnly", athenzClientOnlyHandler)

	if *backend {
		bMgr := &backendMgr{
			reloader:           reloader,
			frontendCommonName: *frontendCommonName,
		}
		defer bMgr.reloader.Close()
		http.HandleFunc("/backend", bMgr.backendHandler)
	}

	if *frontend {
		clientTlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			ServerName: *backendURL,
		}
		clientTlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return reloader.GetLatestCertificate()
		}
		clientTlsConfig.VerifyPeerCertificate = getVerifier(func(cert *x509.Certificate) bool {
			return cert.Subject.CommonName == *backendCommonName
		})

		fMgr := &frontendMgr{
			client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: clientTlsConfig,
				},
				Timeout: 10 * time.Second,
			},
			backendURL: "https://" + *backendURL + ":4443/backend",
		}
		http.HandleFunc("/frontend", fMgr.frontendHandler)
	}

	log.Fatalln(server.ListenAndServeTLS("", ""))
}
