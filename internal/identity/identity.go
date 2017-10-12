package identity

import (
	"crypto"
	"fmt"
	"time"

	"github.com/yahoo/k8s-athenz-identity/internal/util"
	"github.com/pkg/errors"
)

const (
	jwtAudience = "k8s-athenz-identity"
)

// SigningKey encapsulates a signing key
type SigningKey struct {
	URI     string        // the URI that identifies the key
	Type    util.KeyType  // key type
	Value   crypto.Signer // the private key
	Version string        // key version
}

// SigningKeyProvider is a function that can provide a signing key.
type SigningKeyProvider func() (*SigningKey, error)

// AttributeProvider provides attributes given a pod ID.
type AttributeProvider func(podID string) (*PodSubject, error)

type SerializerConfig struct {
	TokenExpiry time.Duration      // JWT expiry
	KeyProvider SigningKeyProvider // signing mechanism
}

func (s *SerializerConfig) initDefaults() {
	if s.TokenExpiry == 0 {
		s.TokenExpiry = 15 * time.Minute
	}
}

func (s *SerializerConfig) assertValid() error {
	return util.CheckFields("SerializerConfig", map[string]bool{
		"KeyProvider": s.KeyProvider == nil,
	})
}

// Serializer serializes a subject into an identity document.
type Serializer struct {
	SerializerConfig
}

func NewSerializer(config SerializerConfig) (*Serializer, error) {
	config.initDefaults()
	if err := config.assertValid(); err != nil {
		return nil, err
	}
	return &Serializer{
		SerializerConfig: config,
	}, nil
}

func (s *Serializer) IdentityDoc(attrs *PodSubject) (string, error) {
	k, err := s.KeyProvider()
	if err != nil {
		return "", errors.Wrap(err,"key provider error")
	}
	subjectURI, err := attrs.toURI()
	if err != nil {
		return "", err
	}
	return signJWT(
		&jwtPayload{
			subject:  subjectURI,
			audience: jwtAudience,
		},
		k,
		s.TokenExpiry,
	)
}

// PublicKeyProvider returns public keys corresponding to an issuer URI
type PublicKeyProvider func(issuerURI string) (pubKey crypto.PublicKey, err error)

// VerifierConfig is the configuration for the verifier.
type VerifierConfig struct {
	AttributeProvider AttributeProvider // return expected attributes for pod
	PublicKeyProvider PublicKeyProvider // return public key for issuer
}

func (s *VerifierConfig) assertValid() error {
	return util.CheckFields("VerifierConfig", map[string]bool{
		"AttributeProvider": s.AttributeProvider == nil,
		"PublicKeyProvider": s.PublicKeyProvider == nil,
	})
}

// Verifier verifies signed identity documents against a pod store.
type Verifier struct {
	VerifierConfig
}

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if err := config.assertValid(); err != nil {
		return nil, err
	}
	return &Verifier{
		VerifierConfig: config,
	}, nil
}

func (v *Verifier) VerifyDoc(identityDoc string) (*PodSubject, error) {
	jwt, err := verifyJWT(identityDoc, v.PublicKeyProvider)
	if err != nil {
		return nil, err
	}
	if jwt.audience != jwtAudience {
		return nil, fmt.Errorf("JWT audience mismatch want %q, got %q", jwtAudience, jwt.audience)
	}
	return verifySubjectURI(jwt.subject, v.AttributeProvider)
}
