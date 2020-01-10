// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the 3-Clause BSD license. See LICENSE file in
// github.com/yahoo/k8s-athenz-identity for terms.

package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ecdsaKeyPEM = `
-----BEGIN ECDSA PRIVATE KEY-----
MGgCAQEEHNarorXgmcHhsf2cOHGXSFG6QsYrxoIPor0RWYmgBwYFK4EEACGhPAM6
AAR7mgsQp1hggjxu1g4FswcJIoJTz6noeh0XxhI/cJ3IczfbnDr6QyAXLXW0u0oL
mcWNDJ2McOHTlA==
-----END ECDSA PRIVATE KEY-----
`

func mustParseURI(t *testing.T, s string) url.URL {
	p, err := url.Parse(s)
	require.Nil(t, err)
	return *p
}

func TestSAN(t *testing.T) {
	a := assert.New(t)
	sans := SubjectAlternateNames{}
	a.True(sans.IsEmpty())

	sans = SubjectAlternateNames{
		DNSNames:       []string{"machine.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.10.10.11"), net.ParseIP("10.10.10.12")},
		EmailAddresses: []string{"john@doe.com"},
		URIs: []url.URL{
			mustParseURI(t, "http://example.com"),
			mustParseURI(t, "http://example.net"),
		},
	}
	a.False(sans.IsEmpty())
	expected := strings.Trim(`
DNS: machine.example.com
IP: 10.10.10.11, 10.10.10.12
URI: http://example.com, http://example.net
Email: john@doe.com`, "\r\n")
	a.Equal(expected, sans.String())
}

func TestReadPublicKey(t *testing.T) {
	a := assert.New(t)
	s := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxwGYT7kfNcFH74pnNz+p
CXb0C8ZP/10NAdWNUanjhDyBNBhsPQ3f80LwQLaZJEQ1hvijouBD3swh0L5/muqQ
Otvfx+940nITXqKuLwsklZKb6HZ4lEkZx+7iBWW3F0z+GdtMDVY/EJ9k0QSWfPhF
SYhEGm7pWzDbOwOIORNmrzBSYLLDRZqDH0IM6crxdrDvTYOYKg6dCQAJFZWKttUt
LCS5tDhZLZhCmAgE8NK32xMJ7jNCuQ25Dh7C+TokuNFGfmSME6TGRDoFQXTK0PBl
U2gA/QAw8Xys85lPbZ3qplJFhCap1b4DaU7zdg6wP309PjUD99RZB8ibV9OC6G6a
AQIDAQAB
-----END PUBLIC KEY-----
`
	key, err := PublicKeyFromPEMBytes([]byte(s))
	require.Nil(t, err)
	rkey, ok := key.(*rsa.PublicKey)
	a.True(ok)
	a.Equal(65537, rkey.E)
}

func TestReadPublicKeyNoPEM(t *testing.T) {
	a := assert.New(t)
	s := `
BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxwGYT7kfNcFH74pnNz+p
CXb0C8ZP/10NAdWNUanjhDyBNBhsPQ3f80LwQLaZJEQ1hvijouBD3swh0L5/muqQ
Otvfx+940nITXqKuLwsklZKb6HZ4lEkZx+7iBWW3F0z+GdtMDVY/EJ9k0QSWfPhF
SYhEGm7pWzDbOwOIORNmrzBSYLLDRZqDH0IM6crxdrDvTYOYKg6dCQAJFZWKttUt
LCS5tDhZLZhCmAgE8NK32xMJ7jNCuQ25Dh7C+TokuNFGfmSME6TGRDoFQXTK0PBl
U2gA/QAw8Xys85lPbZ3qplJFhCap1b4DaU7zdg6wP309PjUD99RZB8ibV9OC6G6a
AQIDAQAB
END PUBLIC KEY-----
`
	_, err := PublicKeyFromPEMBytes([]byte(s))
	require.NotNil(t, err)
	a.Equal("PublicKeyFromPEMBytes: no valid PEM block found", err.Error())
}

func TestReadPrivateKeyRSA(t *testing.T) {
	a := assert.New(t)
	s := `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxwGYT7kfNcFH74pnNz+pCXb0C8ZP/10NAdWNUanjhDyBNBhs
PQ3f80LwQLaZJEQ1hvijouBD3swh0L5/muqQOtvfx+940nITXqKuLwsklZKb6HZ4
lEkZx+7iBWW3F0z+GdtMDVY/EJ9k0QSWfPhFSYhEGm7pWzDbOwOIORNmrzBSYLLD
RZqDH0IM6crxdrDvTYOYKg6dCQAJFZWKttUtLCS5tDhZLZhCmAgE8NK32xMJ7jNC
uQ25Dh7C+TokuNFGfmSME6TGRDoFQXTK0PBlU2gA/QAw8Xys85lPbZ3qplJFhCap
1b4DaU7zdg6wP309PjUD99RZB8ibV9OC6G6aAQIDAQABAoIBACZFzEEo3TO9ZFRR
TeB2QdAsLGtHTINUJfhAVdlqzvLToBWgzNBBJtzl9sa7V2B+Lb0zfGUKtILYx3gZ
6vikO/DV8IfHKnlurwL4Tn+FqReLBqkCf9Yk6OxmqNlY4ol8qTHX1xyJhb9wqDb6
puaJ6OlnZ5Gd2wtKrh7/Yud3L7xpO8EDgQcM7lPWXElCOhg0EN22QjNrS4WNcIpb
dWWe6+EbfcGWRSgvSRqNLNNkmhe5QE8zLXYC83B+TGmS+xFFG447OPHq/7YGXlP2
2lCAvi873i7gHehdPy+dLpveU271WS7D+gyWUiZFSEYlElVyGuLFyWUtLjferSj7
KS+yE/ECgYEA7VdnYXXFJRSo3Wz6vWcBitrHJMyDWbh5uQBeQyyZX9KR4mVmqm9u
RdpfSmtMcPdPqnX5PUctYF2fEouKIPUQQBa/uIU4dJI9ixQz4nT5Jh0eweqiprWW
rRw83CUkutIOzE5ZwvYr/usQH6dJXER4FpLofgfmmLmZtQl/mW53a9cCgYEA1qat
48AdE+5kiW60/+85kRinfc/S8RQPP26Vm9lwqVuy39ENgPPberaLaYJ9T1UcqNLn
yfM1YSZuCnMP3qGL9LUDVHetCZxqEXyvraIEb2PnUYonVZP78cS/r3auqNtQ4Dmt
Mzs0xmkiLYNEi+gU0w0aZGeMg60O3lnboHYUrecCgYEA0/zFcd9m/v+89Elqi9F9
JzDRvqSMjY6f6gXSK92iAFxrwPMhCAoPTIUHp8i+tgevOGm2/GyesvvsIPxRm65H
nXa0N3OGQVh9b8PTs+kWwFwyJLIWJSD8PBKEqXzjmZoVbZZtxh1qnn4GIL+iXq8p
M8BzuF4GMVNVXsXlGn34XHECgYAi1fIqoCcX8PyIAVuGncBt995W4L+POH4xATVu
kZ9jHOquwDK81tar16xQd0j28w0vqOrNL5deKOp676mHrBgWornjn3iJssTUCbRJ
LZ4ipcgIx68SiG2/Evs48r3t0YoSmcmuItGx0aYmVMNvIT8f8WRzHwsC47ciBttJ
81/vyQKBgAYRYlhRc5omi7KvwopDMusablpq1yd4nVblC4ZTr6vw9cCyJeIDHFWb
fsAhJ1OXloN5ALS29OewZ19Ql/07nemHLpdiPqaVgKpFlEna4iR3MNUwz3DjlJh9
YKdO5CW4qnRSMyyaEwQdux7tLQ8l8SLTk3g7CAaQJjzKBCScX+lt
-----END RSA PRIVATE KEY-----
`
	kt, key, err := PrivateKeyFromPEMBytes([]byte(s))
	require.Nil(t, err)
	a.Equal(RSA, kt)
	rkey, ok := key.(*rsa.PrivateKey)
	a.True(ok)
	a.Equal(65537, rkey.E)
}

func TestReadPrivateKeyECDSA(t *testing.T) {
	a := assert.New(t)
	s := ecdsaKeyPEM
	kt, key, err := PrivateKeyFromPEMBytes([]byte(s))
	require.Nil(t, err)
	a.Equal(ECDSA, kt)
	_, ok := key.(*ecdsa.PrivateKey)
	a.True(ok)
}

func TestSANRoundTrip(t *testing.T) {
	a := assert.New(t)
	sans := SubjectAlternateNames{
		DNSNames:       []string{"machine.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.10.10.11"), net.ParseIP("10.10.10.12"), net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")},
		EmailAddresses: []string{"john@doe.com"},
		URIs: []url.URL{
			mustParseURI(t, "http://example.com"),
			mustParseURI(t, "http://example.net"),
		},
	}
	s1 := sans.String()
	ext, err := MarshalSANs(sans)
	require.Nil(t, err)
	sans, err = UnmarshalSANs([]pkix.Extension{ext})
	require.Nil(t, err)
	s2 := sans.String()
	require.Nil(t, err)
	a.EqualValues(s1, s2)
}

func TestEmptySANRoundTrip(t *testing.T) {
	a := assert.New(t)
	sans := SubjectAlternateNames{}
	s1 := sans.String()
	ext, err := MarshalSANs(sans)
	require.Nil(t, err)
	sans, err = UnmarshalSANs([]pkix.Extension{ext})
	require.Nil(t, err)
	s2 := sans.String()
	require.Nil(t, err)
	a.EqualValues(s1, s2)
	sans, err = UnmarshalSANs([]pkix.Extension{})
	require.Nil(t, err)
	s3 := sans.String()
	a.EqualValues(s1, s3)
}

func decodeCSR(t *testing.T, csr []byte) *x509.CertificateRequest {
	var derBytes []byte
	block, _ := pem.Decode(csr)
	require.NotNil(t, block)
	derBytes = block.Bytes
	req, err := x509.ParseCertificateRequest(derBytes)
	require.Nil(t, err)
	err = req.CheckSignature()
	require.Nil(t, err)
	return req
}

func TestGenerateKeyAndCSR(t *testing.T) {
	a := assert.New(t)
	subject := pkix.Name{
		Country:            []string{"US"},
		Province:           []string{"CA"},
		Organization:       []string{"SomeOrg"},
		OrganizationalUnit: []string{"SomeOU"},
		CommonName:         "foo.bar",
	}
	asn1Subject, err := asn1.Marshal(subject.ToRDNSequence())
	require.Nil(t, err)
	sans := SubjectAlternateNames{
		DNSNames:       []string{"machine.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.10.10.11"), net.ParseIP("10.10.10.12")},
		EmailAddresses: []string{"john@doe.com"},
		URIs: []url.URL{
			mustParseURI(t, "http://example.com"),
			mustParseURI(t, "http://example.net"),
		},
	}
	_, csrPEM, err := GenerateKeyAndCSR(CSROptions{
		Subject: subject,
		SANs:    sans,
	})
	require.Nil(t, err)
	req := decodeCSR(t, csrPEM)
	sans2, err := UnmarshalSANs(req.Extensions)
	require.Nil(t, err)
	a.Equal(sans.String(), sans2.String())
	a.Equal(x509.RSA, req.PublicKeyAlgorithm)
	a.Equal(x509.SHA256WithRSA, req.SignatureAlgorithm)
	a.EqualValues(asn1Subject, req.RawSubject)
}

func TestGenerateCSRForECDSA(t *testing.T) {
	a := assert.New(t)
	subject := pkix.Name{
		Country:            []string{"US"},
		Province:           []string{"CA"},
		Organization:       []string{"SomeOrg"},
		OrganizationalUnit: []string{"SomeOU"},
		CommonName:         "foo.bar",
	}
	asn1Subject, err := asn1.Marshal(subject.ToRDNSequence())
	require.Nil(t, err)
	sans := SubjectAlternateNames{
		DNSNames:       []string{"machine.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.10.10.11"), net.ParseIP("10.10.10.12")},
		EmailAddresses: []string{"john@doe.com"},
		URIs: []url.URL{
			mustParseURI(t, "http://example.com"),
			mustParseURI(t, "http://example.net"),
		},
	}
	_, signer, err := PrivateKeyFromPEMBytes([]byte(ecdsaKeyPEM))
	require.Nil(t, err)
	csrPEM, err := GenerateCSR(signer, CSROptions{
		Subject: subject,
		SANs:    sans,
	})
	require.Nil(t, err)
	req := decodeCSR(t, csrPEM)
	sans2, err := UnmarshalSANs(req.Extensions)
	require.Nil(t, err)
	a.Equal(x509.ECDSA, req.PublicKeyAlgorithm)
	a.Equal(x509.ECDSAWithSHA256, req.SignatureAlgorithm)
	a.Equal(sans.String(), sans2.String())
	a.EqualValues(asn1Subject, req.RawSubject)
}
