package common

import (
	"fmt"

	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"k8s.io/api/core/v1"
)

const (
	domainAnnotation  = "athenz/domain"
	serviceAnnotation = "athenz/service"
	AthensInitSecret  = "athens-init-secret"
)

// Pod2Attributes maps a pod object to pod attributes of interest.
// Currently uses annotations but should probably use the service account
// name to extract domain/ service
func Pod2Attributes(pod *v1.Pod) (*identity.PodAttributes, error) {
	a := pod.Annotations
	domain, service := a[domainAnnotation], a[serviceAnnotation]
	if domain == "" {
		return nil, fmt.Errorf("missing annotation %v", domainAnnotation)
	}
	if service == "" {
		return nil, fmt.Errorf("missing annotation %v", serviceAnnotation)
	}
	return &identity.PodAttributes{
		ID:      fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
		Domain:  domain,
		Service: service,
	}, nil
}
