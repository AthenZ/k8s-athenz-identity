package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

type certInfo struct {
	CommonName string   `json:"commonName"`
	DNSNames   []string `json:"dnsNames"`
	DNSIPs     []string `json:"ips"`
}

type field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type response struct {
	Cert   *certInfo `json:"cert"`
	Fields []field   `json:"fields"`
}

func main() {
	certFile := "/var/athenz/tls/service.cert"
	keyFile := "/var/athenz/tls/service.key"
	reloader, err := util.NewCertReloader(util.ReloadConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		log.Fatalln(err)
	}
	defer reloader.Close()
	var info *certInfo
	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		leafBytes := cert.Certificate[0]
		if c, err := x509.ParseCertificate(leafBytes); err == nil {
			info = &certInfo{
				CommonName: c.Subject.CommonName,
				DNSNames:   c.DNSNames,
			}
			for _, ip := range c.IPAddresses {
				info.DNSIPs = append(info.DNSIPs, ip.String())
			}
		}
	}
	server := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetCertificate: func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return reloader.GetLatestCertificate()
			},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			file := "/tokens/ntoken"
			b, err := ioutil.ReadFile(file)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var out []field
			fields := strings.Split(string(b), ";")
			for _, f := range fields {
				parts := strings.SplitN(f, "=", 2)
				if len(parts) == 2 && parts[0] != "s" { // hide sig
					out = append(out, field{Name: parts[0], Value: parts[1]})
				}
			}
			b, err = json.MarshalIndent(response{Fields: out, Cert: info}, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		}),
	}
	log.Fatalln(server.ListenAndServeTLS("", ""))
}
