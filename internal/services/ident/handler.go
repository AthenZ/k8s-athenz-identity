package ident

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"crypto/x509"

	"github.com/dimfeld/httptreemux"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const (
	initPath    = "/init"
	refreshPath = "/refresh"
)

type Identity struct {
	NToken    string `json:"ntoken"`
	KeyPEM    []byte `json:"keyPEM"`
	CertPEM   []byte `json:"certPEM"`
	CACertPem []byte `json:"caCertPEM"`
}

type RefreshRequest struct {
	KeyPEM  []byte `json:"KeyPEM"`
	CertPEM []byte `json:"certPEM"`
}

type Signer func(subject *identity.PodSubject) (string, error)

// identityContext is the context for the identity document.
type identityContext struct {
	Domain          string   // Athenz domain
	Service         string   // Athenz service name
	ProviderService string   // provider service name
	SANNames        []string // SAN names to be registered for the TLS cert
	SANIPs          []string // SAN IPs to be registered for the TLS cert
	InstanceID      string   // instance id returned by Athenz after initial call
}

func (c *identityContext) assertValid() error {
	return util.CheckFields("SIA context", map[string]bool{
		"Domain":          c.Domain == "",
		"Service":         c.Service == "",
		"ProviderService": c.ProviderService == "",
		"SANNames":        len(c.SANNames) == 0,
	})
}

type HandlerConfig struct {
	Signer          Signer
	AttrProvider    identity.AttributeProvider
	ZTSEndpoint     string
	ZTSCAPool       *x509.CertPool
	ProviderService string
	DNSSuffix       string
}

func (h *HandlerConfig) assertValid() error {
	return util.CheckFields("HandlerConfig", map[string]bool{
		"Signer":          h.Signer == nil,
		"AttrProvider":    h.AttrProvider == nil,
		"ZTSEndpoint":     h.ZTSEndpoint == "",
		"ProviderService": h.ProviderService == "",
		"DNSSuffix":       h.DNSSuffix == "",
	})
}

type handler struct {
	HandlerConfig
}

func NewHandler(versionPrefix string, config HandlerConfig) (http.Handler, error) {
	if err := config.assertValid(); err != nil {
		return nil, err
	}
	h := &handler{HandlerConfig: config}
	mux := httptreemux.New()
	mux.POST(versionPrefix+initPath+"/:hashed", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		h.initIdentity(w, r, params["hashed"])
	})
	mux.POST(versionPrefix+refreshPath+"/:hashed", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		h.refreshIdentity(w, r, params["hashed"])
	})
	return mux, nil
}

func (h *handler) doJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func (h *handler) getSubject(handle string) (*identity.PodSubject, *IdentityVolume, error) {
	v := newVolumeFromHashedPath(handle)
	podID, err := v.getID()
	if err != nil {
		return nil, nil, errors.Wrap(err, "volume.getID")
	}
	subject, err := h.AttrProvider(podID.String())
	if err != nil {
		return nil, nil, errors.Wrap(err, "AttrProvider")
	}
	return subject, v, nil
}

func (h *handler) id2Res(id *zts.InstanceIdentity, keyPEM []byte) *Identity {
	return &Identity{
		NToken:    string(id.ServiceToken),
		KeyPEM:    keyPEM,
		CertPEM:   []byte(id.X509Certificate), // TODO: concat with root CA?
		CACertPem: []byte(id.X509CertificateSigner),
	}
}

func (h *handler) makeIdentity(subject *identity.PodSubject) (*Identity, *identityContext, error) {
	handle := func(err error) (*Identity, *identityContext, error) {
		return nil, nil, err
	}
	identityDoc, err := h.Signer(subject)
	if err != nil {
		return handle(errors.Wrap(err, "signing error"))
	}
	dashedDomain := strings.Replace(subject.Domain, ".", "-", -1)
	localName := subject.ID
	if pos := strings.LastIndex(localName, "/"); pos >= 0 {
		localName = localName[pos+1:]
	}
	c := identityContext{
		Domain:          subject.Domain,
		Service:         subject.Service,
		ProviderService: h.ProviderService,
		SANNames: []string{
			fmt.Sprintf("%s.%s.%s", subject.Service, dashedDomain, h.DNSSuffix),
			fmt.Sprintf("%s.instanceid.athenz.%s", localName, h.DNSSuffix),
		},
		SANIPs: []string{
			subject.IP,
		},
	}
	if subject.ServiceIP != "" {
		c.SANIPs = append(c.SANIPs, subject.ServiceIP)

	}
	z, err := newZTS(h.ZTSEndpoint, h.ZTSCAPool, c)
	if err != nil {
		return handle(errors.Wrap(err, "ZTS client create"))
	}

	id, keyPEM, err := z.getIdentity(identityDoc)
	if err != nil {
		return handle(errors.Wrap(err, "ZTS get identity"))
	}
	c.InstanceID = string(id.InstanceId)
	return h.id2Res(id, keyPEM), &c, nil
}

func (h *handler) initIdentity(w http.ResponseWriter, r *http.Request, handle string) {
	// TODO: handle replay for the same pod
	subject, vol, err := h.getSubject(handle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, context, err := h.makeIdentity(subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := vol.saveContext(context); err != nil {
		err := errors.Wrap(err, "saveContext")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.doJSON(w, res)
}

func (h *handler) getRefreshParams(idHandle string, r *http.Request) (*RefreshRequest, *identityContext, error) {
	handle := func(err error) (*RefreshRequest, *identityContext, error) {
		return nil, nil, err
	}
	v := newVolumeFromHashedPath(idHandle)
	var c identityContext
	if err := v.getContext(&c); err != nil {
		return handle(errors.Wrap(err, "vol.getContext"))
	}
	var res RefreshRequest
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return handle(errors.Wrap(err, "body read"))
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return handle(errors.Wrap(err, "JSON unmarshal"))
	}
	return &res, &c, nil
}

func (h *handler) doRefresh(req *RefreshRequest, c identityContext) (*Identity, error) {
	z, err := newZTS(h.ZTSEndpoint, h.ZTSCAPool, c)
	if err != nil {
		return nil, errors.Wrap(err, "ZTS client create")
	}

	id, keyPEM, err := z.refreshIdentity(req.CertPEM, req.KeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "zts refresh identity")
	}
	return h.id2Res(id, keyPEM), nil

}

func (h *handler) refreshIdentity(w http.ResponseWriter, r *http.Request, handle string) {
	req, c, err := h.getRefreshParams(handle, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := h.doRefresh(req, *c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.doJSON(w, res)
}
