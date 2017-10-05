package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"

	"fmt"
	"io/ioutil"

	"github.com/dimfeld/httptreemux"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"go.corp.yahoo.com/clusterville/log"
)

type InstanceRefreshRequest struct {
	Csr        string `json:"csr"`
	ExpiryTime *int32 `json:"expiryTime,omitempty" rdl:"optional"`
}

type Identity struct {
	Name         string `json:"name"`
	Certificate  string `json:"certificate,omitempty"`
	CaCertBundle string `json:"caCertBundle,omitempty"`
	ServiceToken string `json:"serviceToken,omitempty"`
}

type InstanceRegisterInformation struct {
	Provider        string `json:"provider"`
	Domain          string `json:"domain"`
	Service         string `json:"service"`
	AttestationData string `json:"attestationData"`
	Csr             string `json:"csr"`
	Token           *bool  `json:"token,omitempty"`
}

type InstanceRefreshInformation struct {
	Csr   string `json:"csr"`
	Token *bool  `json:"token,omitempty"`
}

type InstanceIdentity struct {
	Provider              string            `json:"provider"`
	Name                  string            `json:"name"`
	InstanceId            string            `json:"instanceId"`
	X509Certificate       string            `json:"x509Certificate,omitempty"`
	X509CertificateSigner string            `json:"x509CertificateSigner,omitempty"`
	ServiceToken          string            `json:"serviceToken,omitempty"`
	Attributes            map[string]string `json:"attributes,omitempty"`
}

type service struct {
	domain string
	name   string
}

type refreshInput struct {
	service
	provider string
	instance string
}

type zts struct {
	caKey     crypto.PrivateKey
	caCert    *x509.Certificate
	caKeyPEM  []byte
	caCertPEM []byte
	dnsSuffix string
}

func newZTS(caCertPEM, caKeyPEM []byte, dnsSuffix string) (*zts, error) {
	_, key, err := util.PrivateKeyFromPEMBytes(caKeyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := loadCert(caCertPEM)
	return &zts{
		caKey:     key,
		caCert:    cert,
		caKeyPEM:  caKeyPEM,
		caCertPEM: caCertPEM,
		dnsSuffix: dnsSuffix,
	}, nil
}

func (z *zts) createCreds(domain, service string, csr []byte) (string, []byte, error) {
	req, err := getCSR([]byte(csr))
	if err != nil {
		return "", nil, err
	}
	out, err := createCert(z.caKey, z.caCert, req)
	if err != nil {
		return "", nil, err
	}
	tb, err := zmssvctoken.NewTokenBuilder(domain, service, z.caKeyPEM, "v1")
	if err != nil {
		return "", nil, err
	}
	tok, err := tb.Token().Value()
	if err != nil {
		return "", nil, err
	}
	return tok, out, nil
}

func (z *zts) decode(r *http.Request, data interface{}) error {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("body read error for %s %v", r.Method, r.URL))
	}
	log.Printf("body for %s %v,\n%s\n", r.Method, r.URL, b)
	err = json.Unmarshal(b, data)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("JSON unmarshal error for %s", b))
	}
	return nil
}

func (z *zts) getInstanceRefreshRequest(r *http.Request) (*InstanceRefreshRequest, error) {
	var in InstanceRefreshRequest
	err := z.decode(r, &in)
	if err != nil {
		return nil, err
	}
	if err := util.CheckFields("InstanceRefreshRequest", map[string]bool{
		"CSR": in.Csr == "",
	}); err != nil {
		return nil, err
	}
	return &in, nil
}

func (z *zts) doJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (z *zts) credentialsForKeyOwner(w http.ResponseWriter, r *http.Request, s service) {
	in, err := z.getInstanceRefreshRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tok, cert, err := z.createCreds(s.domain, s.name, []byte(in.Csr))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	z.doJSON(w, http.StatusOK, &Identity{
		Name:         s.name + "." + strings.Replace(s.domain, ".", "-", -1) + "." + z.dnsSuffix,
		Certificate:  string(cert),
		CaCertBundle: string(z.caCertPEM),
		ServiceToken: tok,
	})
}

func (z *zts) getInstanceRegisterInfo(r *http.Request) (*InstanceRegisterInformation, error) {
	var in InstanceRegisterInformation
	err := z.decode(r, &in)
	if err != nil {
		return nil, err
	}
	if err := util.CheckFields("InstanceRegisterInformation", map[string]bool{
		"CSR":             in.Csr == "",
		"Provider":        in.Provider == "",
		"Domain":          in.Domain == "",
		"Service":         in.Service == "",
		"AttestationData": in.AttestationData == "",
	}); err != nil {
		return nil, err
	}
	return &in, nil
}

func (z *zts) providerRegistration(w http.ResponseWriter, r *http.Request) {
	in, err := z.getInstanceRegisterInfo(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tok, cert, err := z.createCreds(in.Domain, in.Service, []byte(in.Csr))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	z.doJSON(w, http.StatusCreated, &InstanceIdentity{
		Provider:              in.Provider,
		Name:                  in.Service + "." + strings.Replace(in.Domain, ".", "-", -1) + "." + z.dnsSuffix,
		InstanceId:            "i1",
		X509Certificate:       string(cert),
		X509CertificateSigner: string(z.caCertPEM),
		ServiceToken:          tok,
	})
}

func (z *zts) getInstanceRefreshInfo(r *http.Request) (*InstanceRefreshRequest, error) {
	var in InstanceRefreshRequest
	err := z.decode(r, &in)
	if err != nil {
		return nil, err
	}
	if err := util.CheckFields("InstanceRefreshRequest", map[string]bool{
		"CSR": in.Csr == "",
	}); err != nil {
		return nil, err
	}
	return &in, nil
}

func (z *zts) providerRefresh(w http.ResponseWriter, r *http.Request, ri refreshInput) {
	in, err := z.getInstanceRefreshInfo(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tok, cert, err := z.createCreds(ri.domain, ri.name, []byte(in.Csr))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	z.doJSON(w, http.StatusOK, &InstanceIdentity{
		Provider:              ri.provider,
		Name:                  ri.name + "." + strings.Replace(ri.domain, ".", "-", -1) + "." + z.dnsSuffix,
		InstanceId:            "i1",
		X509Certificate:       string(cert),
		X509CertificateSigner: string(z.caKeyPEM),
		ServiceToken:          tok,
	})
}

func (z *zts) handler(prefix string) http.Handler {
	router := httptreemux.New()
	router.POST(prefix+"/instance/:domain/:service/refresh", func(w http.ResponseWriter, r *http.Request, ps map[string]string) {
		z.credentialsForKeyOwner(w, r, service{
			domain: ps["domain"],
			name:   ps["service"],
		})
	})
	router.POST(prefix+"/instance", func(w http.ResponseWriter, r *http.Request, ps map[string]string) {
		z.providerRegistration(w, r)
	})
	router.POST(prefix+"/instance/:provider/:domain/:service/:instanceId", func(w http.ResponseWriter, r *http.Request, ps map[string]string) {
		z.providerRefresh(w, r, refreshInput{
			service: service{
				domain: ps["domain"],
				name:   ps["service"],
			},
			instance: ps["instanceId"],
			provider: ps["provider"],
		})
	})
	return router
}
