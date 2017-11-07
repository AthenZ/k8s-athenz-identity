// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package identity

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/internal/util"
)

const (
	iss = "iss"
	alg = "alg"
)

var signingMethods = map[util.KeyType]string{
	util.RSA:   "RS256",
	util.ECDSA: "EC256",
}

// jwtPayload is the payload for the JWT not including the standard claims that are
// automatically added.
type jwtPayload struct {
	subject  string // the subject URI of the JWT
	audience string // the audience for which the JWT is valid
}

// signJWT signs the payload using the specified attributes.
func signJWT(payload *jwtPayload, key *SigningKey, expiry time.Duration) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(expiry).Unix(),
		Issuer:    key.URI,
		Subject:   payload.subject,
		Audience:  payload.audience,
		IssuedAt:  time.Now().Unix(),
	}

	str, ok := signingMethods[key.Type]
	if !ok {
		return "", fmt.Errorf("unknown signing algorithm %v", key.Type)
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(str), claims)
	token.Header[iss] = key.URI
	signedString, err := token.SignedString(key.Value)
	if err != nil {
		return "", errors.Wrap(err, "error signing jwt token")
	}
	return signedString, nil
}

// verifyJWT verifies the supplied token using the supplied public key provider.
// In addition, it automatically checks for valid signing algorithms and token expiry.
func verifyJWT(token string, keyProvider PublicKeyProvider) (*jwtPayload, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		issuerURI := token.Header[iss].(string)
		alg := token.Header[alg].(string)
		if alg != "RS256" && alg != "EC256" {
			return nil, fmt.Errorf("unsupported signing algorithm %s", alg)
		}
		return keyProvider(issuerURI)
	})
	if err != nil {
		return nil, errors.Wrap(err, "token parse error")
	}

	claims := jwtToken.Claims.(*jwt.StandardClaims)
	return &jwtPayload{
		subject:  claims.Subject,
		audience: claims.Audience,
	}, nil

}
