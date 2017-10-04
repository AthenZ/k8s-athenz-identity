package main

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

var wantToken = true

type ztsClient struct {
	endpoint string
	payload  *identity.SIAPayload
}

func newZTS(endpoint string, payload *identity.SIAPayload) *ztsClient {
	return &ztsClient{
		endpoint: endpoint,
		payload:  payload,
	}
}

func (z *ztsClient) generateKeyAndCSR() (keyPEM, csrPEM []byte, err error) {
	payload := z.payload
	return util.GenerateKeyAndCSR(fmt.Sprintf("%s.%s", payload.Domain, payload.Service), util.CSROptions{
		DNSNames:    payload.SANNames,
		IPAddresses: nil, // TODO: fix this
	})
}

type refreshCredentials struct {
	instanceID string
	cert       tls.Certificate
}

func (z *ztsClient) identity2Creds(identity *zts.InstanceIdentity, keyPEM []byte) (*refreshCredentials, error) {
	cert, err := tls.X509KeyPair([]byte(identity.X509Certificate), keyPEM)
	if err != nil {
		return nil, err
	}
	return &refreshCredentials{
		instanceID: string(identity.InstanceId),
		cert:       cert,
	}, nil

}

func (z *ztsClient) getIdentity() (*zts.InstanceIdentity, []byte, *refreshCredentials, error) {
	handle := func(err error) (*zts.InstanceIdentity, []byte, *refreshCredentials, error) {
		return nil, nil, nil, err
	}
	payload := z.payload
	keyPEM, csrPEM, err := z.generateKeyAndCSR()
	if err != nil {
		return handle(err)
	}
	client := zts.NewClient(z.endpoint, nil)
	identity, _, err := client.PostInstanceRegisterInformation(&zts.InstanceRegisterInformation{
		Provider:        zts.ServiceName(payload.ProviderService),
		Domain:          zts.DomainName(payload.Domain),
		Service:         zts.SimpleName(payload.Service),
		AttestationData: payload.IdentityDoc,
		Csr:             string(csrPEM),
		Token:           &wantToken,
	})
	if err != nil {
		return handle(err)
	}
	creds, err := z.identity2Creds(identity, keyPEM)
	if err != nil {
		return handle(err)
	}
	return identity, keyPEM, creds, err
}

func (z *ztsClient) refreshIdentity(creds *refreshCredentials) (*zts.InstanceIdentity, []byte, *refreshCredentials, error) {
	handle := func(err error) (*zts.InstanceIdentity, []byte, *refreshCredentials, error) {
		return nil, nil, nil, err
	}
	client := zts.NewClient(z.endpoint, &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{creds.cert},
		},
	})
	payload := z.payload
	keyPEM, csrPEM, err := z.generateKeyAndCSR()
	if err != nil {
		return handle(err)
	}
	identity, err := client.PostInstanceRefreshInformation(
		zts.ServiceName(payload.ProviderService),
		zts.DomainName(payload.Domain),
		zts.SimpleName(payload.Service),
		zts.PathElement(creds.instanceID),
		&zts.InstanceRefreshInformation{
			Csr:   string(csrPEM),
			Token: &wantToken,
		})
	if err != nil {
		return handle(err)
	}
	newCreds, err := z.identity2Creds(identity, keyPEM)
	if err != nil {
		return handle(err)
	}
	return identity, keyPEM, newCreds, err
}
