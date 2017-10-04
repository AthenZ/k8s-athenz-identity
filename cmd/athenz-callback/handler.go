package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

type instanceConfirmation struct {
	Provider        string            `json:"provider"`
	Domain          string            `json:"domain"`
	Service         string            `json:"service"`
	AttestationData string            `json:"attestationData"`
	Attributes      map[string]string `json:"attributes,omitempty"`
}

type handler struct {
	verifier *identity.Verifier
}

func (ic *instanceConfirmation) assertValid() error {
	return util.CheckFields("instance confirmation", map[string]bool{
		"Provider":        ic.Provider == "",
		"Domain":          ic.Domain == "",
		"Service":         ic.Service == "",
		"AttestationData": ic.AttestationData == "",
	})
}

func (h *handler) getConfirmation(r *http.Request) (*instanceConfirmation, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("bad HTTP method %s want post", r.Method)
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, errors.Wrap(err, "body read")
	}
	var ic instanceConfirmation
	err = json.Unmarshal(b, &ic)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("JSON unmarshal, %q", b))
	}
	err = ic.assertValid()
	if err != nil {
		return nil, err
	}
	return &ic, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// FIXME: mask errors from client and log real ones
	// TODO: replay handling checks, persist pod annotation of processed pods and check for replay
	ic, err := h.getConfirmation(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	attrs, err := h.verifier.VerifyDoc(ic.AttestationData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if attrs.Domain != ic.Domain || attrs.Service != ic.Service {
		http.Error(w, "domain/service mismatch", http.StatusForbidden)
		return
	}
	json.NewEncoder(w).Encode(ic)
}
