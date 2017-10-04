package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func newSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	out, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("rand.Int: %v", err)
	}
	return out, nil
}

func getCSR(csr []byte) (*x509.CertificateRequest, error) {
	var derBytes []byte
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, errors.New("cannot parse CSR (empty pem)")
	}
	derBytes = block.Bytes
	req, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificateRequest: %v", err)
	}
	err = req.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("req.CheckSignature: %v", err)
	}
	return req, nil
}

func createCert(key crypto.PrivateKey, cert *x509.Certificate, csr *x509.CertificateRequest) ([]byte, error) {
	notBefore := time.Now().Add(-10 * time.Minute)
	notAfter := time.Now().Add(24 * time.Hour)
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          serial,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	c, err := x509.CreateCertificate(rand.Reader, template, cert, csr.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c,
	}), nil

}

func loadCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	return cert, nil
}
