// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.
package util

import (
	"fmt"
	"net/url"
	"strings"
)

// NamespaceToDomain converts a kube namespace to an Athenz domain
func NamespaceToDomain(ns string) (domain string) {
	//TODO: handle system namespaces
	dotted := strings.Replace(ns, "-", ".", -1)
	return strings.Replace(dotted, "..", "-", -1)
}

// ServiceAccountToService converts a kube serviceaccount name to an Athenz service
func ServiceAccountToService(svc string) string {
	return svc
}

// SpiffeURI returns the SPIFFE URI for the specified Athens domain and service.
func SpiffeURI(domain, service string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/sa/%s", domain, service))
}

// DomainToDNSPart converts the Athenz domain into a DNS label
func DomainToDNSPart(domain string) (part string) {
	return strings.Replace(domain, ".", "-", -1)
}
