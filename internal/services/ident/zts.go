package ident

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/k8s-athenz-identity/internal/services/config"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

var wantToken = true

type ztsClient struct {
	endpoint string
	tls      *tls.Config
	sanIPs   []net.IP
	context  identityContext
}

func newZTS(endpoint string, cc *config.ClusterConfiguration, context identityContext) (*ztsClient, error) {
	var sanIPs []net.IP
	for _, str := range context.SANIPs {
		ip := net.ParseIP(str)
		if ip == nil {
			return nil, fmt.Errorf("invalid SAN IP %q", str)
		}
	}
	conf, err := cc.ClientTLSConfig(config.AthenzRoot)
	if err != nil {
		return nil, err
	}
	return &ztsClient{
		endpoint: endpoint,
		tls:      conf,
		sanIPs:   sanIPs,
		context:  context,
	}, nil
}

func (z *ztsClient) generateKeyAndCSR() (keyPEM, csrPEM []byte, err error) {
	ctx := z.context
	return util.GenerateKeyAndCSR(fmt.Sprintf("%s.%s", ctx.Domain, ctx.Service), util.CSROptions{
		DNSNames:    ctx.SANNames,
		IPAddresses: z.sanIPs,
	})
}

func (z *ztsClient) getIdentity(identityDoc string) (*zts.InstanceIdentity, []byte, error) {
	handle := func(err error) (*zts.InstanceIdentity, []byte, error) {
		return nil, nil, err
	}
	ctx := z.context
	keyPEM, csrPEM, err := z.generateKeyAndCSR()
	if err != nil {
		return handle(err)
	}
	client := zts.NewClient(z.endpoint, &http.Transport{
		TLSClientConfig: z.tls,
	})
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
	return id, keyPEM, err
}

func (z *ztsClient) refreshIdentity(certPEM, keyPEM []byte) (*zts.InstanceIdentity, []byte, error) {
	handle := func(err error) (*zts.InstanceIdentity, []byte, error) {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		handle(err)
	}

	cfg := *z.tls
	cfg.Certificates = []tls.Certificate{cert}
	client := zts.NewClient(z.endpoint, &http.Transport{
		TLSClientConfig: &cfg,
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
	return id, keyPEM, err
}
