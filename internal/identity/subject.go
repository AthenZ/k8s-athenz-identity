package identity

import (
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const (
	scheme       = "pod"
	paramDomain  = "d"
	paramService = "s"
)

// PodAttributes is the set of pod attributes that need to be verified in the flow.
type PodAttributes struct {
	ID      string
	Domain  string
	Service string
}

func (s *PodAttributes) assertValid() error {
	return util.CheckFields("PodAttributes", map[string]bool{
		"ID":      s.ID == "",
		"Domain":  s.Domain == "",
		"Service": s.Service == "",
	})
}

func (s *PodAttributes) toURI() (string, error) {
	if err := s.assertValid(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s?%s=%s&%s=%s",
			scheme,
			s.ID,
			paramDomain, s.Domain,
			paramService, s.Service),
		nil
}

func (s *PodAttributes) fromURI(u string) error {
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
	return s.assertValid()
}

func verifySubjectURI(u string, provider AttributeProvider) (*PodAttributes, error) {
	attrs := &PodAttributes{}
	err := attrs.fromURI(u)
	if err != nil {
		return nil, err
	}

	expectedAttrs, err := provider(attrs.ID)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("attribute provider for %s", attrs.ID))
	}

	if *expectedAttrs != *attrs {
		return nil, fmt.Errorf("attribute mismatch want %+v, got %+v", expectedAttrs, attrs)
	}
	return attrs, nil
}
