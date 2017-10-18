package main

import (
	"fmt"
	"time"

	"crypto/tls"

	"net/http"

	"github.com/yahoo/athenz/clients/go/zts"
	"github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

var (
	defaultExpiry = 7 * 24 * time.Hour
)

type keySource func() (keyPEM []byte, keyVersion string, err error)

type ztsConfig struct {
	endpoint   string
	authHeader string
	ks         keySource
	domain     string
	service    string
	opts       util.CSROptions
	tls        *tls.Config
}

func (z *ztsConfig) assertValid() error {
	return util.CheckFields("ztsConfig", map[string]bool{
		"endpoint":   z.endpoint == "",
		"authHeader": z.authHeader == "",
		"domain":     z.domain == "",
		"service":    z.service == "",
		"ks":         z.ks == nil,
	})
}

type ztsClient struct {
	ztsConfig
}

func newClient(config ztsConfig) (*ztsClient, error) {
	if err := config.assertValid(); err != nil {
		return nil, err
	}
	return &ztsClient{ztsConfig: config}, nil
}

func (z *ztsClient) getCertificate() (ntoken string, cert []byte, caCert []byte, err error) {
	handleError := func(err error) (string, []byte, []byte, error) {
		return "", nil, nil, err
	}
	key, ver, err := z.ks()
	if err != nil {
		return handleError(err)
	}
	_, signer, err := util.PrivateKeyFromPEMBytes(key)
	if err != nil {
		return handleError(err)
	}
	csr, err := util.GenerateCSR(signer, fmt.Sprintf("%s.%s", z.domain, z.service), z.opts)
	if err != nil {
		return handleError(err)
	}
	var d = int32(defaultExpiry / time.Second)
	req := &zts.InstanceRefreshRequest{
		Csr:        string(csr),
		ExpiryTime: &d,
	}
	tb, err := zmssvctoken.NewTokenBuilder(z.domain, z.service, key, ver)
	if err != nil {
		return handleError(err)
	}
	token, err := tb.Token().Value()
	if err != nil {
		return handleError(err)
	}
	client := zts.NewClient(z.endpoint, &http.Transport{
		TLSClientConfig: z.tls,
	})
	client.AddCredentials(z.authHeader, token)
	identity, err := client.PostInstanceRefreshRequest(
		zts.CompoundName(z.domain),
		zts.SimpleName(z.service),
		req,
	)
	if err != nil {
		return handleError(err)
	}
	if identity.Certificate == "" {
		return handleError(fmt.Errorf("blank TLS cert returned from server"))
	}
	// we create a bucket of certs to create a self-contained
	// bundle.
	return token,
		[]byte(identity.Certificate + identity.CaCertBundle),
		[]byte(identity.CaCertBundle),
		nil
}
