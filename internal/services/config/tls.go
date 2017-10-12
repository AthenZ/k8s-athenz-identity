package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

// standardCipherSuites returns a list of acceptable cipher suites in priority order of use.
func standardCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, // not implemented in Go stdlib as of Go 1.9
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		// tls.TLS_RSA_WITH_AES_256_CBC_SHA256, // not implemented in Go stdlib as of Go 1.9
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
}

func makeConfig(override func(*tls.Config)) *tls.Config {
	c := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             standardCipherSuites(),
		SessionTicketsDisabled:   true,
		PreferServerCipherSuites: true,
	}
	override(c)
	return c
}

func getVerifier(allowFn func(*x509.Certificate) bool) func([][]byte, [][]*x509.Certificate) error {
	if allowFn == nil {
		return nil
	}
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, certs := range verifiedChains {
			leaf := certs[0]
			if allowFn(leaf) {
				return nil
			}
		}
		return fmt.Errorf("client identity verification failed")
	}
}

type Credentials struct {
	KeyFile  string
	CertFile string
}

type VerifyClient struct {
	Source TrustedSource
	Allow  func(cert *x509.Certificate) bool
}

func (c *ClusterConfiguration) ClientTLSConfig(src TrustedSource) (*tls.Config, error) {
	pool, err := c.trustRoot(src)
	if err != nil {
		return nil, err
	}
	return makeConfig(func(config *tls.Config) {
		config.RootCAs = pool
	}), nil
}

func (c *ClusterConfiguration) ClientTLSConfigWithCreds(creds Credentials, src TrustedSource) (*tls.Config, io.Closer, error) {
	pool, err := c.trustRoot(src)
	if err != nil {
		return nil, nil, err
	}
	reloader, err := newCertReloader(reloadConfig{
		KeyFile:  creds.KeyFile,
		CertFile: creds.CertFile,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "create cert reloader")
	}
	return makeConfig(func(conf *tls.Config) {
		conf.RootCAs = pool
		conf.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return reloader.GetLatestCertificate()
		}
	}), reloader, nil
}

func (c *ClusterConfiguration) ServerTLSConfig(creds Credentials, vc VerifyClient) (*tls.Config, io.Closer, error) {
	var pool *x509.CertPool
	var err error
	if vc.Source != AnySource {
		pool, err = c.trustRoot(vc.Source)
		if err != nil {
			return nil, nil, err
		}
	}
	reloader, err := newCertReloader(reloadConfig{
		KeyFile:  creds.KeyFile,
		CertFile: creds.CertFile,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "create cert reloader")
	}
	return makeConfig(func(conf *tls.Config) {
		conf.ClientCAs = pool
		conf.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return reloader.GetLatestCertificate()
		}
		conf.VerifyPeerCertificate = getVerifier(vc.Allow)
		if vc.Source == AnySource && vc.Allow == nil {
			conf.ClientAuth = tls.VerifyClientCertIfGiven
		} else {
			conf.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}), reloader, nil
}
