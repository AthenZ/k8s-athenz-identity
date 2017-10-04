package util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/pkg/errors"
)

// KeyType is the type of private key.
type KeyType int

const (
	_ KeyType = iota
	RSA
	ECDSA
)

type CSROptions struct {
	DNSNames    []string
	IPAddresses []net.IP
}

func LoadCACerts(file string) (*x509.CertPool, error) {
	var pool *x509.CertPool
	if file == "" {
		return pool, nil
	}
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %v", err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("error loading any cert from %s", file)
	}
	return pool, nil
}

func generateKey() (*rsa.PrivateKey, []byte, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("could not generate private key: %v", err)
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
	return k, keyPEM, nil
}

func PublicKeyFromPEMBytes(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PublicKeyFromPEMBytes: no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "PublicKeyFromPEMBytes")
	}
	return key, nil
}

func PrivateKeyFromPEMBytes(privatePEMBytes []byte) (KeyType, crypto.Signer, error) {
	handle := func(err error) (KeyType, crypto.Signer, error) {
		return 0, nil, errors.Wrap(err, "PrivateKeyFromPEMBytes")
	}
	block, _ := pem.Decode(privatePEMBytes)
	if block == nil {
		return handle(fmt.Errorf("unable to load private key, invalid PEM block: %s", privatePEMBytes))
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return handle(err)
		}
		return ECDSA, k, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return handle(err)
		}
		return RSA, k, nil
	default:
		return handle(fmt.Errorf("unsupported private key type: %s", block.Type))
	}
}

func GenerateCSR(signer crypto.Signer, commonName string, opts CSROptions) (csrPEM []byte, err error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           opts.DNSNames,
		IPAddresses:        opts.IPAddresses,
	}
	var csr []byte
	csr, err = x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		err = errors.Wrap(err, "cannot create CSR")
		return
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
	return
}

func GenerateKeyAndCSR(commonName string, opts CSROptions) (keyPEM, csrPEM []byte, err error) {
	var k *rsa.PrivateKey
	k, keyPEM, err = generateKey()
	if err != nil {
		return
	}
	csrPEM, err = GenerateCSR(k, commonName, opts)
	return
}
