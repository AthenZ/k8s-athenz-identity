// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

// Package keys provides a mechanism to get versioned keys.
package util

import (
	"crypto"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// SigningKey encapsulates a signing key
type SigningKey struct {
	URI     string        // the URI that identifies the key
	Type    KeyType       // key type
	Value   crypto.Signer // the private key
	Version string        // key version
}

type versionedFiles struct {
	dir    string
	prefix string
}

type fv struct {
	file       string
	version    int
	versionStr string
}

func (f *versionedFiles) list() ([]fv, error) {
	var ret []fv
	prefix := f.prefix + ".v"
	if files, err := ioutil.ReadDir(f.dir); err == nil {
		for _, file := range files {
			name := file.Name()
			if !strings.HasPrefix(name, prefix) {
				log.Printf("invalid versioned file '%s', does not start with '%s'", name, prefix)
				continue
			}
			v := strings.TrimPrefix(name, prefix)
			if version, err := strconv.Atoi(v); err == nil {
				ret = append(ret, fv{
					file:       filepath.Join(f.dir, name),
					version:    version,
					versionStr: fmt.Sprintf("v%d", version),
				})
			} else {
				log.Printf("invalid version '%s' for file '%s'\n", v, name)
			}
		}
	} else {
		return nil, errors.Wrap(err, "list files")
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("no versioned files under %s", f.dir)
	}
	return ret, nil
}

func (f *versionedFiles) latestVersionContents() ([]byte, string, error) {
	fvs, err := f.list()
	if err != nil {
		return nil, "", err
	}
	sort.Slice(fvs, func(i, j int) bool {
		return fvs[i].version < fvs[j].version
	})
	fv := fvs[len(fvs)-1]
	content, err := ioutil.ReadFile(fv.file)
	if err != nil {
		return nil, "", err
	}
	return content, fv.versionStr, nil
}

func (f *versionedFiles) contentsForVersion(version string) ([]byte, error) {
	fvs, err := f.list()
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, fv := range fvs {
		if fv.versionStr == version {
			return ioutil.ReadFile(fv.file)
		}
		versions = append(versions, fv.versionStr)
	}
	return nil, fmt.Errorf("no file with version %s, have %v", version, versions)
}

func secretURI(name, version string) string {
	return fmt.Sprintf("secret:%s?version=%s", name, version)
}

func parseSecretURI(uri, expectedName string) (version string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("parseSecretURI: %s", uri))
	}
	if u.Scheme != "secret" {
		return "", fmt.Errorf("parseSecretURI: %s, invalid scheme %s, want 'secret'", uri, u.Scheme)
	}
	if u.Opaque != expectedName {
		return "", fmt.Errorf("parseSecretURI: %s, invalid name %q, want %q", uri, u.Opaque, expectedName)
	}
	v := u.Query().Get("version")
	if v == "" {
		return "", fmt.Errorf("parseSecretURI: %s, no version found", uri)
	}
	return v, nil
}

// PrivateKeySource returns signing keys using the latest version found in a directory.
type PrivateKeySource struct {
	secretName string
	files      *versionedFiles
}

// NewPrivateKeySource returns a private key source that uses files in the supplied directory
// having the supplied prefix. Files in the directory must be named <secret-name>.v<n> to
// be considered. Sorting is not lexicographic; "v10" sorts higher than "v9"
func NewPrivateKeySource(dir string, secretName string) *PrivateKeySource {
	return &PrivateKeySource{
		secretName: secretName,
		files: &versionedFiles{
			dir:    dir,
			prefix: secretName,
		},
	}
}

// SigningKey returns the current signing key.
func (pks *PrivateKeySource) SigningKey() (*SigningKey, error) {
	contents, version, err := pks.files.latestVersionContents()
	if err != nil {
		return nil, err
	}
	keyType, key, err := PrivateKeyFromPEMBytes(contents)
	if err != nil {
		return nil, err
	}
	return &SigningKey{
		URI:     secretURI(pks.secretName, version),
		Type:    keyType,
		Value:   key,
		Version: version,
	}, nil
}

// PublicKeySource returns public keys for specific key versions.
type PublicKeySource struct {
	secretName string
	files      *versionedFiles
}

// NewPublicKeySource returns a public key source that uses files in the supplied directory
// having the supplied prefix. Files in the directory must be named <secret-name>.v<n> to
// be considered.
func NewPublicKeySource(dir string, secretName string) *PublicKeySource {
	return &PublicKeySource{
		secretName: secretName,
		files: &versionedFiles{
			dir:    dir,
			prefix: secretName,
		},
	}
}

// PublicKey returns the public key for the supplied issuer URI.
func (pks *PublicKeySource) PublicKey(issuerURI string) (pubKey crypto.PublicKey, err error) {
	version, err := parseSecretURI(issuerURI, pks.secretName)
	if err != nil {
		return nil, err
	}
	contents, err := pks.files.contentsForVersion(version)
	if err != nil {
		return nil, err
	}
	return PublicKeyFromPEMBytes(contents)
}
