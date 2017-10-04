package identity

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const (
	jwtAudience    = "k8s-athenz-identity"
	envDomain      = "SIA_IN_DOMAIN"
	envService     = "SIA_IN_SERVICE"
	envProvider    = "SIA_IN_PROVIDER_SERVICE"
	envIdentityDoc = "SIA_IN_IDENTITY_DOC"
	envSANNames    = "SIA_IN_SAN_NAMES"
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
type AttributeProvider func(podID string) (*PodAttributes, error)

// Context is the context for the identity document.
type Context struct {
	Domain          string   // Athenz domain
	Service         string   // Athenz service name
	ProviderService string   // provider service name
	SANNames        []string // SAN names to be registered for the TLS cert
}

func (c *Context) assertValid() error {
	return util.CheckFields("SIA context", map[string]bool{
		"Domain":          c.Domain == "",
		"Service":         c.Service == "",
		"ProviderService": c.ProviderService == "",
		"SANNames":        len(c.SANNames) == 0,
	})
}

// SIAPayload the identity document and associated context. Can be serialized to and
// deserialized from a map.
type SIAPayload struct {
	Context
	IdentityDoc string
}

func (s *SIAPayload) assertValid() error {
	err := s.Context.assertValid()
	if err != nil {
		return err
	}
	if s.IdentityDoc == "" {
		return fmt.Errorf("invalid SIA payload, no identity doc")
	}
	return nil
}

func (s *SIAPayload) toEnv() (map[string]string, error) {
	if err := s.assertValid(); err != nil {
		return nil, err
	}
	return map[string]string{
		envDomain:      s.Domain,
		envService:     s.Service,
		envProvider:    s.ProviderService,
		envIdentityDoc: s.IdentityDoc,
		envSANNames:    strings.Join(s.SANNames, ","),
	}, nil
}

func (s *SIAPayload) fromEnv(env map[string]string) error {
	s.Context = Context{
		Domain:          env[envDomain],
		Service:         env[envService],
		ProviderService: env[envProvider],
		SANNames:        strings.Split(env[envSANNames], ","),
	}
	s.IdentityDoc = env[envIdentityDoc]
	return s.assertValid()
}

type SerializerConfig struct {
	TokenExpiry     time.Duration      // JWT expiry
	KeyProvider     SigningKeyProvider // signing mechanism
	DNSSuffix       string             // DNS suffix for TLS SAN names
	ProviderService string             // service name of provider
}

func (s *SerializerConfig) initDefaults() {
	if s.TokenExpiry == 0 {
		s.TokenExpiry = 15 * time.Minute
	}
}

func (s *SerializerConfig) assertValid() error {
	return util.CheckFields("SerializerConfig", map[string]bool{
		"KeyProvider":     s.KeyProvider == nil,
		"DNSSuffix":       s.DNSSuffix == "",
		"ProviderService": s.ProviderService == "",
	})
}

// Serializer serializes an SIA payload into a map of key value pairs.
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

func (s *Serializer) extractContext(attrs *PodAttributes) (*Context, error) {
	localName := attrs.ID
	pos := strings.LastIndex(localName, "/")
	if pos >= 0 {
		localName = localName[pos+1:]
	}
	dashedDomain := strings.Replace(attrs.Domain, ".", "-", -1)
	return &Context{
		Domain:          attrs.Domain,
		Service:         attrs.Service,
		ProviderService: s.ProviderService,
		SANNames: []string{
			fmt.Sprintf("%s.%s.%s", attrs.Service, dashedDomain, s.DNSSuffix),
			fmt.Sprintf("%s.instanceid.athenz.%s", localName, s.DNSSuffix),
		},
	}, nil
}

func (s *Serializer) makeIdentityDoc(attrs *PodAttributes, k *SigningKey) (string, error) {
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

func (s *Serializer) Serialize(attrs *PodAttributes) (map[string]string, error) {
	ctx, err := s.extractContext(attrs)
	if err != nil {
		return nil, err
	}

	k, err := s.KeyProvider()
	if err != nil {
		return nil, err
	}

	doc, err := s.makeIdentityDoc(attrs, k)
	if err != nil {
		return nil, err
	}
	payload := &SIAPayload{
		Context:     *ctx,
		IdentityDoc: doc,
	}
	p, err := payload.toEnv()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func PayloadFromEnvironment(env map[string]string) (*SIAPayload, error) {
	if env == nil {
		return nil, fmt.Errorf("illegal argument: nil map for deserialization")
	}
	payload := &SIAPayload{}
	if err := payload.fromEnv(env); err != nil {
		return nil, err
	}
	return payload, nil
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

func (v *Verifier) VerifyDoc(identityDoc string) (*PodAttributes, error) {
	jwt, err := verifyJWT(identityDoc, v.PublicKeyProvider)
	if err != nil {
		return nil, err
	}
	if jwt.audience != jwtAudience {
		return nil, fmt.Errorf("JWT audience mismatch want %q, got %q", jwtAudience, jwt.audience)
	}
	return verifySubjectURI(jwt.subject, v.AttributeProvider)
}
