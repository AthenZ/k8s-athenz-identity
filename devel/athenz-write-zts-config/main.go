// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/ghodss/yaml"
	"github.com/yahoo/k8s-athenz-identity/devel/mock"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	var (
		providerService  = "k8s.admin.athenz-identityd"
		providerEndpoint = "https://athenz-identityd.k8s-admin.svc.cluster.local:4443"
		cbService        = "k8s.admin.athenz-identityd"
		cbPublicKey      = "athenz-identityd.pub.pem"
		cbKeyVersion     = "v1"
		jwtService       = "k8s.admin.athenz-jwt-service"
		jwtKeyVersion    = "v1"
		jwtPublicKey     = "jwt-service.pub.pem"
	)

	flag.StringVar(&providerService, "provider-service", providerService, "provider service name in Athenz format")
	flag.StringVar(&providerEndpoint, "provider-endpoint", providerEndpoint, "provider endpoint")

	flag.StringVar(&cbService, "identityd-service", cbService, "identityd service name")
	flag.StringVar(&cbPublicKey, "identityd-public-key", cbPublicKey, "identityd public key file")
	flag.StringVar(&cbKeyVersion, "identityd-version", cbKeyVersion, "identityd key version")

	flag.StringVar(&jwtService, "jwt-service", jwtService, "JWT service name")
	flag.StringVar(&jwtPublicKey, "jwt-public-key", jwtPublicKey, "JWT public key file")
	flag.StringVar(&jwtKeyVersion, "jwt-version", jwtKeyVersion, "JWT key version")

	flag.Parse()

	cbb, err := ioutil.ReadFile(cbPublicKey)
	if err != nil {
		log.Fatalln(err)
	}
	jwtb, err := ioutil.ReadFile(jwtPublicKey)
	if err != nil {
		log.Fatalln(err)
	}

	c := &mock.ZTSConfig{
		ProviderEndpoints: map[string]string{
			providerService: providerEndpoint,
		},
		PublicKeys: []mock.PublicKey{
			{
				Service: cbService,
				Version: cbKeyVersion,
				PEM:     string(cbb),
			},
			{
				Service: jwtService,
				Version: jwtKeyVersion,
				PEM:     string(jwtb),
			},
		},
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		log.Fatalln(err)
	}
	cm := v1.ConfigMap{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "mock-zts-config",
		},
		Data: map[string]string{
			"config.yaml": string(b),
		},
	}
	b, err = yaml.Marshal(cm)
	if err != nil {
		log.Fatalln(err)
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte{'\n'})
}
