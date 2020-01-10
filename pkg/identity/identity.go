// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.
package identity

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

// IdentityConfig from cmd line args
type IdentityConfig struct {
	Init            bool
	KeyFile         string
	CertFile        string
	CaCertFile      string
	Refresh         time.Duration
	Mode            string
	Reloader        *util.CertReloader
	SaTokenFile     string
	Endpoint        string
	ProviderService string
	DNSSuffix       string
	Namespace       string
	Serviceaccount  string
	PodIP           string
	PodUID          string
}

func generateKeyAndCSR(idConfig IdentityConfig) (keyPEM, csrPEM []byte, err error) {

	domain := util.NamespaceToDomain(idConfig.Namespace)
	domainDNSPart := util.DomainToDNSPart(domain)
	service := util.ServiceAccountToService(idConfig.Serviceaccount)
	ip := net.ParseIP(idConfig.PodIP)
	if ip == nil {
		return nil, nil, errors.New("Pod IP is nil")
	}
	spiffeURI, err := util.SpiffeURI(domain, service)
	if err != nil {
		return nil, nil, err
	}

	sans := []string{
		fmt.Sprintf("%s.%s.%s", service, domainDNSPart, idConfig.DNSSuffix),
		fmt.Sprintf("*.%s.%s.%s", service, domainDNSPart, idConfig.DNSSuffix),
		fmt.Sprintf("%s.instanceid.athenz.%s", idConfig.PodUID, idConfig.DNSSuffix),
	}

	subject := pkix.Name{
		OrganizationalUnit: []string{idConfig.ProviderService},
		CommonName:         fmt.Sprintf("%s.%s", domain, service),
	}

	csrOptions := util.CSROptions{
		Subject: subject,
		SANs: util.SubjectAlternateNames{
			DNSNames:    sans,
			IPAddresses: []net.IP{ip},
			URIs:        []url.URL{*spiffeURI},
		},
	}
	return util.GenerateKeyAndCSR(csrOptions)
}

func GetX509Cert(idConfig IdentityConfig) (*zts.InstanceIdentity, []byte, error) {
	keyPEM, csrPEM, err := generateKeyAndCSR(idConfig)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if !idConfig.Init {
		cert, err := idConfig.Reloader.GetLatestCertificate()
		if err != nil {
			return nil, nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	client := zts.NewClient(idConfig.Endpoint, &http.Transport{
		TLSClientConfig: tlsConfig,
	})

	domain := util.NamespaceToDomain(idConfig.Namespace)
	service := util.ServiceAccountToService(idConfig.Serviceaccount)
	saToken, err := ioutil.ReadFile(idConfig.SaTokenFile)
	if err != nil {
		return nil, nil, err
	}

	if idConfig.Init {
		id, _, err := client.PostInstanceRegisterInformation(&zts.InstanceRegisterInformation{
			Provider:        zts.ServiceName(idConfig.ProviderService),
			Domain:          zts.DomainName(domain),
			Service:         zts.SimpleName(service),
			AttestationData: string(saToken),
			Csr:             string(csrPEM),
		})
		return id, keyPEM, err
	}

	id, err := client.PostInstanceRefreshInformation(
		zts.ServiceName(idConfig.ProviderService),
		zts.DomainName(domain),
		zts.SimpleName(service),
		zts.PathElement(idConfig.PodUID),
		&zts.InstanceRefreshInformation{
			AttestationData: string(saToken),
			Csr:             string(csrPEM),
		})

	return id, keyPEM, err
}
