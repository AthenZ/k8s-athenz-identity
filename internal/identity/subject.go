// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package identity

import (
	"fmt"
	"log"
	"net/url"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"k8s.io/api/core/v1"
)

const (
	scheme       = "pod"
	paramDomain  = "d"
	paramService = "n"
	paramIP      = "i"
)

// PodSubject is the set of pod attributes that need to be verified in the flow.
type PodSubject struct {
	ID      string
	Domain  string
	Service string
	IP      string
}

func (s *PodSubject) assertValid() error {
	return util.CheckFields("PodSubject", map[string]bool{
		"ID":      s.ID == "",
		"Domain":  s.Domain == "",
		"Service": s.Service == "",
		"IP":      s.IP == "",
	})
}

func (s *PodSubject) toURI() (string, error) {
	esc := url.QueryEscape
	if err := s.assertValid(); err != nil {
		return "", err
	}
	suffix := ""
	return fmt.Sprintf("%s:%s?%s=%s&%s=%s&%s=%s%s",
			scheme,
			s.ID,
			paramDomain, esc(s.Domain),
			paramService, esc(s.Service),
			paramIP, esc(s.IP),
			suffix,
		),
		nil
}

func (s *PodSubject) fromURI(u string) error {
	uri, err := url.Parse(u)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("uri %q parse error", u))
	}
	if uri.Scheme != scheme {
		return fmt.Errorf("uri %q: bad scheme, want %q got %q", u, scheme, uri.Scheme)
	}
	q := uri.Query()
	s.ID = uri.Opaque
	s.Domain = q.Get(paramDomain)
	s.Service = q.Get(paramService)
	s.IP = q.Get(paramIP)
	return s.assertValid()
}

func verifySubjectURI(u string, provider AttributeProvider) (*PodSubject, error) {
	attrs := &PodSubject{}
	err := attrs.fromURI(u)
	if err != nil {
		return nil, err
	}

	expectedAttrs, err := provider(attrs.ID)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("attribute provider for %s", attrs.ID))
	}

	log.Printf("expected=%+v, actual=%+v\n", *expectedAttrs, *attrs)
	if *expectedAttrs != *attrs {
		return nil, fmt.Errorf("attribute mismatch want %+v, got %+v", expectedAttrs, attrs)
	}
	return attrs, nil
}

// Mapper maps pod attributes to a subject.
type Mapper struct {
	config *config.ClusterConfiguration
}

// NewMapper returns a mapper that can provide pod attributes for a pod object.
func NewMapper(c *config.ClusterConfiguration) *Mapper {
	return &Mapper{
		config: c,
	}
}

// GetSubject maps a pod to a subject.
func (m *Mapper) GetSubject(pod *v1.Pod) (*PodSubject, error) {
	domain := m.config.NamespaceToDomain(pod.Namespace)
	service := pod.Spec.ServiceAccountName
	return &PodSubject{
		ID:      fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
		Domain:  domain,
		Service: service,
		IP:      pod.Status.PodIP,
	}, nil
}
