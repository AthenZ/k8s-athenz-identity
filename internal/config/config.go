package config

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"

	"flag"

	"github.com/ghodss/yaml"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

// TrustedSource is a source that can be trusted using CA certs.
type TrustedSource string

const (
	AnySource   TrustedSource = ""               // trust any source
	AthenzRoot  TrustedSource = "athenz"         // root CA to use to trust the Athenz service itself
	ServiceRoot TrustedSource = "athenz-service" // root CA for certs minted by Athenz
)

// isSystemNamespace returns true if the namespace is a system namespace.
func isSystemNamespace(ns string) bool {
	return strings.HasPrefix(ns, "kube-")
}

func mangleDomain(domain string) (namespace string) {
	dubdash := strings.Replace(domain, "-", "--", -1)
	return strings.Replace(dubdash, ".", "-", -1)
}

func unmangleDomain(ns string) (domain string) {
	dotted := strings.Replace(ns, "-", ".", -1)
	return strings.Replace(dotted, "..", "-", -1)
}

// ClusterConfiguration is the config for the cluster
type ClusterConfiguration struct {
	DNSSuffix       string                   `json:"dns-suffix"`       // the DNS suffix for kube-dns as well as Athenz minted certs
	AdminDomain     string                   `json:"admin-domain"`     // the admin domain used for namespace to domain mapping
	ZTSEndpoint     string                   `json:"zts-endpoint"`     // ZTS endpoint with /v1 path
	ProviderService string                   `json:"provider-service"` // the provider service as a fully qualified Athenz name
	TrustRoots      map[TrustedSource]string `json:"trust-roots"`      // CA certs for various trusted sources
	AuthHeader      string                   `json:"auth-header"`      // auth header name for Athenz requests
}

func (c *ClusterConfiguration) trustRoot(src TrustedSource) (*x509.CertPool, error) {
	b, ok := c.TrustRoots[src]
	if !ok {
		return nil, fmt.Errorf("no trust root found for %s", src)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b)) {
		return nil, fmt.Errorf("unable to append certificates for root %s", src)
	}
	return pool, nil
}

func (c *ClusterConfiguration) ServiceURLHost(domain, service string) string {
	return fmt.Sprintf("%s.%s.%s", service, mangleDomain(domain), c.DNSSuffix)
}

func (c *ClusterConfiguration) NamespaceToDomain(ns string) (domain string) {
	if isSystemNamespace(ns) {
		domain = fmt.Sprintf("%s.%s", c.AdminDomain, ns)
	} else {
		domain = unmangleDomain(ns)
	}
	return domain
}

func (c *ClusterConfiguration) DomainToNamespace(domain string) (namespace string) {
	if strings.HasPrefix(domain, c.AdminDomain+".") {
		return domain[len(c.AdminDomain)+1:]
	}
	return mangleDomain(domain)
}

func CmdLine(f *flag.FlagSet) func() (*ClusterConfiguration, error) {
	file := util.EnvOrDefault("CONFIG_URL", "/var/cluster/config.yaml")
	f.StringVar(&file, "config", file, "cluster config file path")
	return func() (*ClusterConfiguration, error) {
		b, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var c ClusterConfiguration
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, err
		}
		return &c, nil
	}
}
