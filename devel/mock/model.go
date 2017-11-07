// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the BSD-3-Clause license. See LICENSE file for terms.

package mock

// PublicKey is the public key information for a service and key version.
type PublicKey struct {
	Service string `json:"service"`
	Version string `json:"version"`
	PEM     string `json:"pem"`
}

// ZTSConfig is the configuration for the mock Athenz implementation.
type ZTSConfig struct {
	PublicKeys        []PublicKey       `json:"public-keys"`
	ProviderEndpoints map[string]string `json:"provider-endpoints"`
}
