package common

import (
	"fmt"
	"strings"

	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"k8s.io/api/core/v1"
)

const (
	domainAnnotation  = "athenz/domain"
	serviceAnnotation = "athenz/service"
	AthensInitSecret  = "athens-init-secret"
)

// isSystemNamespace returns true if the namespace is a system namespace.
func isSystemNamespace(ns string) bool {
	return strings.HasPrefix(ns, "kube-")
}

// restoreDomainName restores the original Athens domain name from the namespace name.
// This assumes that Athenz domains are turned into DNS-safe k8s namespaces
// by converting dots to dashes and literal dashes to two consecutive dashes.
// Thus, an Athenz domain called "foo.bar-baz" is turned into the k8s "foo-bar--baz"
// namespace. This function reverses the mapping to get the original name back.
func restoreDomainName(ns string) string {
	domain := strings.Replace(ns, "-", ".", -1)
	return strings.Replace(domain, "..", "-", -1)
}

type Attributes struct {
	AdminDomain string
}

// Pod2Attributes maps a pod object to pod attributes of interest.
// Currently uses annotations but should probably use the service account
// name to extract domain/ service
func (a *Attributes) Pod2Attributes(pod *v1.Pod) (*identity.PodAttributes, error) {
	ns := pod.Namespace
	var domain string
	if isSystemNamespace(ns) {
		domain = fmt.Sprintf("%s.%s", a.AdminDomain, ns)
	} else {
		domain = ns
	}
	domain = restoreDomainName(domain)
	return &identity.PodAttributes{
		ID:      fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
		Domain:  domain,
		Service: pod.Spec.ServiceAccountName,
	}, nil
}
