package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/internal/identity"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

var wantToken = true

type ztsClient struct {
	endpoint string
	sanIPs   []net.IP
	context  identity.Context
}

func newZTS(endpoint string, context identity.Context, sanIPs []net.IP) *ztsClient {
	return &ztsClient{
		endpoint: endpoint,
		sanIPs:   sanIPs,
		context:  context,
	}
}

func (z *ztsClient) generateKeyAndCSR() (keyPEM, csrPEM []byte, err error) {
	ctx := z.context
	return util.GenerateKeyAndCSR(fmt.Sprintf("%s.%s", ctx.Domain, ctx.Service), util.CSROptions{
		DNSNames:    ctx.SANNames,
		IPAddresses: z.sanIPs,
	})
}

func (z *ztsClient) identity2Creds(identity *zts.InstanceIdentity, keyPEM []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(identity.X509Certificate), keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil

}

func (z *ztsClient) getIdentity(identityDoc string) (*zts.InstanceIdentity, []byte, *tls.Certificate, error) {
	handle := func(err error) (*zts.InstanceIdentity, []byte, *tls.Certificate, error) {
		return nil, nil, nil, err
	}
	ctx := z.context
	keyPEM, csrPEM, err := z.generateKeyAndCSR()
	if err != nil {
		return handle(err)
	}
	client := zts.NewClient(z.endpoint, nil)
	id, _, err := client.PostInstanceRegisterInformation(&zts.InstanceRegisterInformation{
		Provider:        zts.ServiceName(ctx.ProviderService),
		Domain:          zts.DomainName(ctx.Domain),
		Service:         zts.SimpleName(ctx.Service),
		AttestationData: identityDoc,
		Csr:             string(csrPEM),
		Token:           &wantToken,
	})
	if err != nil {
		return handle(err)
	}
	cert, err := z.identity2Creds(id, keyPEM)
	if err != nil {
		return handle(err)
	}
	return id, keyPEM, cert, err
}

func (z *ztsClient) refreshIdentity(cert *tls.Certificate) (*zts.InstanceIdentity, []byte, *tls.Certificate, error) {
	handle := func(err error) (*zts.InstanceIdentity, []byte, *tls.Certificate, error) {
		return nil, nil, nil, err
	}
	client := zts.NewClient(z.endpoint, &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
		},
	})
	ctx := z.context
	keyPEM, csrPEM, err := z.generateKeyAndCSR()
	if err != nil {
		return handle(err)
	}
	id, err := client.PostInstanceRefreshInformation(
		zts.ServiceName(ctx.ProviderService),
		zts.DomainName(ctx.Domain),
		zts.SimpleName(ctx.Service),
		zts.PathElement(ctx.InstanceID),
		&zts.InstanceRefreshInformation{
			Csr:   string(csrPEM),
			Token: &wantToken,
		})
	if err != nil {
		return handle(err)
	}
	newCreds, err := z.identity2Creds(id, keyPEM)
	if err != nil {
		return handle(err)
	}
	return id, keyPEM, newCreds, err
}
