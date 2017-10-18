package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/ghodss/yaml"
	"github.com/yahoo/k8s-athenz-identity/internal/config"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	var (
		dnsSuffix       = "svc.cluster.local"
		adminDomain     = "k8s.admin"
		athenzRootFile  = "athenz-ca.pub.pem"
		serviceRootFile = "athenz-root-ca.pub.pem"
		ztsEndpoint     = "https://mock-athenz.k8s-admin.svc.cluster.local:4443/zts/v1"
		providerService = "k8s.admin.athenz-callback"
		authHeader      = "Athenz-Principal-Auth"
		wrap            = false
	)
	flag.BoolVar(&wrap, "wrap", wrap, "wrap config in config map")
	flag.StringVar(&dnsSuffix, "dns-suffix", dnsSuffix, "cluster DNS suffix")
	flag.StringVar(&adminDomain, "admin-domain", adminDomain, "admin/ cluster domain")
	flag.StringVar(&athenzRootFile, "athenz-ca", athenzRootFile, "CA for trusting Athenz servers")
	flag.StringVar(&serviceRootFile, "root-ca", serviceRootFile, "CA for trusting Athenz-signed TLS certs")
	flag.StringVar(&ztsEndpoint, "zts-endpoint", ztsEndpoint, "ZTS endpoint")
	flag.StringVar(&providerService, "provider-service", providerService, "provider service name in Athenz format")
	flag.StringVar(&authHeader, "auth-header", authHeader, "Athenz auth header name")
	flag.Parse()

	athenzCA, err := ioutil.ReadFile(athenzRootFile)
	if err != nil {
		log.Fatalln(err)
	}
	rootCA, err := ioutil.ReadFile(serviceRootFile)
	if err != nil {
		log.Fatalln(err)
	}

	c := &config.ClusterConfiguration{
		DNSSuffix:   dnsSuffix,
		AdminDomain: adminDomain,
		TrustRoots: map[config.TrustedSource]string{
			config.AthenzRoot:  string(athenzCA),
			config.ServiceRoot: string(rootCA),
		},
		ZTSEndpoint:     ztsEndpoint,
		ProviderService: providerService,
		AuthHeader:      authHeader,
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		log.Fatalln(err)
	}
	if wrap {
		cm := v1.ConfigMap{
			TypeMeta: meta_v1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: "v1",
			},
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "athenz-config",
			},
			Data: map[string]string{
				"config.yaml": string(b),
			},
		}
		b, err = yaml.Marshal(cm)
		if err != nil {
			log.Fatalln(err)
		}
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte{'\n'})
}
