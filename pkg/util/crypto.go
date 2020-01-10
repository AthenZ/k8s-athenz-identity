// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// KeyType is the type of private key.
type KeyType int

// supported key types
const (
	_ KeyType = iota
	RSA
	ECDSA
)

// SubjectAlternateNames contains the SAN entities in a cert.
type SubjectAlternateNames struct {
	DNSNames       []string
	IPAddresses    []net.IP
	URIs           []url.URL
	EmailAddresses []string
}

func (s *SubjectAlternateNames) IsEmpty() bool {
	return len(s.DNSNames) == 0 && len(s.IPAddresses) == 0 && len(s.EmailAddresses) == 0 && len(s.URIs) == 0
}

func (s SubjectAlternateNames) String() string {
	var snips []string
	if len(s.DNSNames) > 0 {
		snips = append(snips, fmt.Sprintf("DNS: %s", strings.Join(s.DNSNames, ", ")))
	}
	if len(s.IPAddresses) > 0 {
		var list []string
		for _, ip := range s.IPAddresses {
			list = append(list, ip.String())
		}
		snips = append(snips, fmt.Sprintf("IP: %s", strings.Join(list, ", ")))
	}
	if len(s.URIs) > 0 {
		var list []string
		for _, u := range s.URIs {
			list = append(list, u.String())
		}
		snips = append(snips, fmt.Sprintf("URI: %s", strings.Join(list, ", ")))
	}
	if len(s.EmailAddresses) > 0 {
		snips = append(snips, fmt.Sprintf("Email: %s", strings.Join(s.EmailAddresses, ", ")))
	}
	return strings.Join(snips, "\n")
}

// CSROptions has optional config for creating a CSR request
type CSROptions struct {
	Subject pkix.Name
	SANs    SubjectAlternateNames
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

// CertificateFromPEMBytes returns an X.509 certificate from its supplied PEM representation.
func CertificateFromPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("CertificateFromPEMBytes: unable to decode x509 cert pem")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "CertificateFromPEMBytes: unable to parse x509 cert")
	}
	return x509Cert, nil
}

// PublicKeyFromPEMBytes returns a public key from its supplied PEM representation.
func PublicKeyFromPEMBytes(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PublicKeyFromPEMBytes: no valid PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "PublicKeyFromPEMBytes")
	}
	return key, nil
}

// PrivateKeyFromPEMBytes returns a private key along with its type from its supplied
// PEM representation.
func PrivateKeyFromPEMBytes(privatePEMBytes []byte) (KeyType, crypto.Signer, error) {
	handle := func(err error) (KeyType, crypto.Signer, error) {
		return 0, nil, errors.Wrap(err, "PrivateKeyFromPEMBytes")
	}
	block, _ := pem.Decode(privatePEMBytes)
	if block == nil {
		return handle(fmt.Errorf("unable to load private key, invalid PEM block: %s", privatePEMBytes))
	}
	switch block.Type {
	case "ECDSA PRIVATE KEY":
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

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

func parseSANExtension(value []byte) (sans SubjectAlternateNames, err error) {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	var rest []byte
	if rest, err = asn1.Unmarshal(value, &seq); err != nil {
		return
	} else if len(rest) != 0 {
		err = fmt.Errorf("x509: trailing data after X.509 extension")
		return
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		err = asn1.StructuralError{Msg: "bad SAN sequence"}
		return
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return
		}
		switch v.Tag {
		case 1:
			sans.EmailAddresses = append(sans.EmailAddresses, string(v.Bytes))
		case 2:
			sans.DNSNames = append(sans.DNSNames, string(v.Bytes))
		case 7:
			switch len(v.Bytes) {
			case net.IPv4len, net.IPv6len:
				sans.IPAddresses = append(sans.IPAddresses, v.Bytes)
			default:
				err = errors.New("x509: certificate contained IP address of length " + strconv.Itoa(len(v.Bytes)))
				return
			}
		case 6:
			u, uerr := url.Parse(string(v.Bytes))
			if uerr != nil {
				err = fmt.Errorf("invalid URI '%s', %v", string(v.Bytes), uerr)
				return
			}
			sans.URIs = append(sans.URIs, *u)
		}
	}
	return
}

func UnmarshalSANs(extensions []pkix.Extension) (sans SubjectAlternateNames, err error) {
	for _, e := range extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return parseSANExtension(e.Value)
		}
	}
	return
}

func MarshalSANs(sans SubjectAlternateNames) (pkix.Extension, error) {
	var rawValues []asn1.RawValue
	for _, name := range sans.DNSNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range sans.EmailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range sans.IPAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}
	for _, u := range sans.URIs {
		rawValues = append(rawValues, asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(u.String())})
	}
	b, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    oidExtensionSubjectAltName,
		Value: b,
	}, nil
}

// GenerateCSR generates a CSR using the supplied key, common name and options.
func GenerateCSR(signer crypto.Signer, opts CSROptions) (csrPEM []byte, err error) {
	algo := x509.SHA256WithRSA
	if _, ok := signer.(*ecdsa.PrivateKey); ok {
		algo = x509.ECDSAWithSHA256
	}
	template := x509.CertificateRequest{
		Subject:            opts.Subject,
		SignatureAlgorithm: algo,
	}
	if !opts.SANs.IsEmpty() {
		ext, err := MarshalSANs(opts.SANs)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = []pkix.Extension{ext}
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

// GenerateKeyAndCSR generates a private key and returns the key and CSR PEMs.
func GenerateKeyAndCSR(opts CSROptions) (keyPEM, csrPEM []byte, err error) {
	var k *rsa.PrivateKey
	k, keyPEM, err = generateKey()
	if err != nil {
		return
	}
	csrPEM, err = GenerateCSR(k, opts)
	return
}
