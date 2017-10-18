package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dimfeld/httptreemux"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/k8s-athenz-identity/devel/mock"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

// Identity is the identity returned by Athenz for the control plane SIA
type Identity struct {
	Name         string `json:"name"`
	Certificate  string `json:"certificate,omitempty"`
	CaCertBundle string `json:"caCertBundle,omitempty"`
	ServiceToken string `json:"serviceToken,omitempty"`
}

// InstanceRefreshRequest is the request to refresh a TLS cert.
// The client needs to identify itself using the previous key and cert
// in its TLS config.
type InstanceRefreshRequest struct {
	Csr        string `json:"csr"`
	ExpiryTime *int32 `json:"expiryTime,omitempty" rdl:"optional"`
}

// InstanceRegisterInformation is the payload to Athenz
// from an SIA agent for initial register.
type InstanceRegisterInformation struct {
	Provider        string `json:"provider"`
	Domain          string `json:"domain"`
	Service         string `json:"service"`
	AttestationData string `json:"attestationData"`
	Csr             string `json:"csr"`
	Token           *bool  `json:"token,omitempty"`
}

// InstanceIdentity is the identity returned by Athenz for the data plane SIA
type InstanceIdentity struct {
	Provider              string            `json:"provider"`
	Name                  string            `json:"name"`
	InstanceID            string            `json:"instanceId"`
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
	authHeader string
	cc         *config.ClusterConfiguration
	config     *mock.ZTSConfig
	tls        *tls.Config
	caKey      crypto.PrivateKey
	caCert     *x509.Certificate
	caKeyPEM   []byte
	caCertPEM  []byte
	dnsSuffix  string
}

func newZTS(tls *tls.Config, caCertPEM, caKeyPEM []byte, cc *config.ClusterConfiguration, zc *mock.ZTSConfig) (*zts, error) {
	_, key, err := util.PrivateKeyFromPEMBytes(caKeyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := loadCert(caCertPEM)
	return &zts{
		authHeader: cc.AuthHeader,
		cc:         cc,
		config:     zc,
		tls:        tls,
		caKey:      key,
		caCert:     cert,
		caKeyPEM:   caKeyPEM,
		caCertPEM:  caCertPEM,
		dnsSuffix:  cc.DNSSuffix,
	}, nil
}

func (z *zts) decode(r *http.Request, data interface{}) error {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("body read error for %s %v", r.Method, r.URL))
	}
	err = json.Unmarshal(b, data)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("JSON unmarshal error for %s", b))
	}
	return nil
}

func (z *zts) doJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
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

func (z *zts) CredentialsForKeyOwner(w http.ResponseWriter, r *http.Request, s service) {
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

type instanceConfirmation struct {
	Provider        string            `json:"provider"`
	Domain          string            `json:"domain"`
	Service         string            `json:"service"`
	AttestationData string            `json:"attestationData"`
	Attributes      map[string]string `json:"attributes,omitempty"`
}

func (z *zts) ProviderRegistration(w http.ResponseWriter, r *http.Request) {
	in, err := z.getInstanceRegisterInfo(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	endpoint := z.config.ProviderEndpoints[in.Provider]
	if endpoint == "" {
		http.Error(w, "no provider registered for "+in.Provider, http.StatusBadRequest)
		return
	}

	confirm := &instanceConfirmation{
		Provider:        in.Provider,
		Domain:          in.Domain,
		Service:         in.Service,
		AttestationData: in.AttestationData,
		Attributes:      map[string]string{}, //TODO: add client IP and SAN IPs as discussed with Athenz team
	}
	b, err := json.Marshal(confirm)
	if err != nil {
		http.Error(w, "confirmation serialization error", http.StatusInternalServerError)
		return
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: z.tls,
		},
	}
	u := endpoint + "/identity"
	res, err := client.Post(u, "application/json", bytes.NewBuffer(b))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	b, _ = ioutil.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("confirmation failed %d, %s", res.StatusCode, b), http.StatusForbidden)
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
		InstanceID:            "i1",
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

func (z *zts) ProviderRefresh(w http.ResponseWriter, r *http.Request, ri refreshInput) {
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
		InstanceID:            "i1",
		X509Certificate:       string(cert),
		X509CertificateSigner: string(z.caKeyPEM),
		ServiceToken:          tok,
	})
}

func (z *zts) handler(prefix string) http.Handler {
	router := httptreemux.New()
	router.POST(prefix+"/instance/:domain/:service/refresh", func(w http.ResponseWriter, r *http.Request, ps map[string]string) {
		z.CredentialsForKeyOwner(w, r, service{
			domain: ps["domain"],
			name:   ps["service"],
		})
	})
	router.POST(prefix+"/instance", func(w http.ResponseWriter, r *http.Request, ps map[string]string) {
		z.ProviderRegistration(w, r)
	})
	router.POST(prefix+"/instance/:provider/:domain/:service/:instanceId", func(w http.ResponseWriter, r *http.Request, ps map[string]string) {
		z.ProviderRefresh(w, r, refreshInput{
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
