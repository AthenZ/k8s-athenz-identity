package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"strings"

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

func getVerifier(allowed []string) func([][]byte, [][]*x509.Certificate) error {
	if len(allowed) == 0 {
		return nil
	}
	m := map[string]bool{}
	for _, a := range allowed {
		m[a] = true
	}
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, certs := range verifiedChains {
			leaf := certs[0]
			if m[leaf.Subject.CommonName] {
				return nil
			}
		}
		return fmt.Errorf("VerifyCommonName: no cert with expected common name %v", allowed)
	}
}

func certPoolFromCAFile(file string) (*x509.CertPool, error) {
	if file == "" {
		return nil, nil
	}
	var pem []byte
	if strings.HasPrefix(file, "http://") {
		res, err := http.Get(file)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("GET %s", file))
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("GET %s returned %d code", file, res.StatusCode)
		}
		pem, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("GET %s, body read error: %v", file, err)
		}
	} else {
		var err error
		pem, err = ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("CA cert %s, %v", file, err)
		}
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("unable to load any CA certs from %s", file)
	}
	return pool, nil
}

type Config struct {
	KeyFile      string
	CertFile     string
	CACertFile   string
	AllowedPeers []string
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

func BaseClientConfig() *tls.Config {
	return makeConfig(func(c *tls.Config) {})
}

func ClientConfig(c Config) (*tls.Config, io.Closer, error) {
	reloader, err := newCertReloader(reloadConfig{
		KeyFile:  c.KeyFile,
		CertFile: c.CertFile,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "create cert reloader")
	}
	pool, err := certPoolFromCAFile(c.CACertFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "load cert pool")
	}
	return makeConfig(func(conf *tls.Config) {
		conf.RootCAs = pool
		conf.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return reloader.GetLatestCertificate()
		}
		conf.VerifyPeerCertificate = getVerifier(c.AllowedPeers)
	}), reloader, nil
}

func ServerConfig(c Config) (*tls.Config, io.Closer, error) {
	reloader, err := newCertReloader(reloadConfig{
		KeyFile:  c.KeyFile,
		CertFile: c.CertFile,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "create cert reloader")
	}
	pool, err := certPoolFromCAFile(c.CACertFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "load cert pool")
	}
	auth := tls.VerifyClientCertIfGiven
	if len(c.AllowedPeers) > 0 {
		auth = tls.RequireAndVerifyClientCert
	}
	return makeConfig(func(conf *tls.Config) {
		conf.ClientAuth = auth
		conf.ClientCAs = pool
		conf.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return reloader.GetLatestCertificate()
		}
		conf.VerifyPeerCertificate = getVerifier(c.AllowedPeers)
	}), reloader, nil
}
