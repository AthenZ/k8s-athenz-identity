// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

// Package ident provides a client and handler implementation for the identity agent.
package ident

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/dimfeld/httptreemux"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"github.com/yahoo/k8s-athenz-identity/internal/volume"
)

const (
	initPath    = "/init"
	refreshPath = "/refresh"
)

// Identity has all the artifacts to prove workload identity.
type Identity struct {
	NToken    string `json:"ntoken"`
	KeyPEM    []byte `json:"keyPEM"`
	CertPEM   []byte `json:"certPEM"`
	CACertPem []byte `json:"caCertPEM"`
}

// RefreshRequest is the input for identity refresh.
type RefreshRequest struct {
	KeyPEM  []byte `json:"keyPEM"`  // the prior key
	CertPEM []byte `json:"certPEM"` // the prior cert
}

// Signer produces an identity document for a pod subject.
type Signer func(subject *identity.PodSubject) (string, error)

// identityContext is the context for the identity document.
type identityContext struct {
	Domain          string    // Athenz domain
	Service         string    // Athenz service name
	ProviderService string    // provider service name
	SANNames        []string  // SAN names to be registered for the TLS cert
	SANIPs          []string  // SAN IPs to be registered for the TLS cert
	SANURIs         []url.URL // SAN URIs to be registered for TLS cert
	InstanceID      string    // instance id returned by Athenz after initial call
}

func (c *identityContext) assertValid() error {
	return util.CheckFields("SIA context", map[string]bool{
		"Domain":          c.Domain == "",
		"Service":         c.Service == "",
		"ProviderService": c.ProviderService == "",
		"SANNames":        len(c.SANNames) == 0,
	})
}

// HandlerConfig is the configuration for the identity handler.
type HandlerConfig struct {
	Signer        Signer                       // used to sign JWTs
	AttrProvider  identity.AttributeProvider   // used to extract a pod subject from attributes
	ZTSEndpoint   string                       // Athenz endpoint
	ClusterConfig *config.ClusterConfiguration // cluster config
}

func (h *HandlerConfig) assertValid() error {
	return util.CheckFields("HandlerConfig", map[string]bool{
		"Signer":        h.Signer == nil,
		"AttrProvider":  h.AttrProvider == nil,
		"ZTSEndpoint":   h.ZTSEndpoint == "",
		"ClusterConfig": h.ClusterConfig == nil,
	})
}

type handler struct {
	HandlerConfig
	locker *idLock
}

// NewHandler returns the identity agent handler for the supplied leading path and configuration.
func NewHandler(versionPrefix string, config HandlerConfig) (http.Handler, error) {
	if err := config.assertValid(); err != nil {
		return nil, err
	}
	h := &handler{HandlerConfig: config, locker: newIDLock()}
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

func (h *handler) getSubject(handle string) (*identity.PodSubject, *volume.IdentityVolume, error) {
	v := volume.NewFromHashedPath(handle)
	podID, err := v.PodIdentifier()
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

	//u, err := h.ClusterConfig.SpiffeURI(subject.Domain, subject.Service)
	//if err != nil {
	//	return handle(errors.Wrap(err, "SPIFFE URL generation"))
	//}

	c := identityContext{
		Domain:          subject.Domain,
		Service:         subject.Service,
		ProviderService: h.ClusterConfig.ProviderService,
		SANNames: []string{
			fmt.Sprintf("%s.%s.%s", subject.Service, dashedDomain, h.ClusterConfig.DNSSuffix),
			fmt.Sprintf("%s.instanceid.athenz.%s", localName, h.ClusterConfig.DNSSuffix),
		},
		SANIPs: []string{
			subject.IP,
		},
		SANURIs: []url.URL{},
	}
	z, err := newZTS(h.ZTSEndpoint, h.ClusterConfig, c)
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
	unlockFn := h.locker.lockHandle(handle)
	defer unlockFn()

	subject, vol, err := h.getSubject(handle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = vol.LoadContext(&identityContext{})
	if err != volume.ErrNoContextFound {
		http.Error(w, "unable to init identity", http.StatusForbidden)
		return
	}

	res, context, err := h.makeIdentity(subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := vol.SaveContext(context); err != nil {
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
	v := volume.NewFromHashedPath(idHandle)
	var c identityContext
	if err := v.LoadContext(&c); err != nil {
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
	z, err := newZTS(h.ZTSEndpoint, h.ClusterConfig, c)
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
