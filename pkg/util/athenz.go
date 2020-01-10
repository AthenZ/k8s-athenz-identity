package util

import (
	"fmt"
	"net/url"
	"strings"
)

func NamespaceToDomain(ns string) (domain string) {
	//TODO: handle system namespaces
	dotted := strings.Replace(ns, "-", ".", -1)
	return strings.Replace(dotted, "..", "-", -1)
}

func ServiceAccountToService(svc string) string {
	return svc
}

// SpiffeURI returns the SPIFFE URI for the specified Athens domain and service.
func SpiffeURI(domain, service string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/sa/%s", domain, service))
}

func DomainToDNSPart(domain string) (part string) {
	return strings.Replace(domain, ".", "-", -1)
}
