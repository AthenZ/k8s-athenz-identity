package mock

type PublicKey struct {
	Service string `json:"service"`
	Version string `json:"version"`
	PEM     string `json:"pem"`
}

type ZTSConfig struct {
	PublicKeys        []PublicKey       `json:"public-keys"`
	ProviderEndpoints map[string]string `json:"provider-endpoints"`
}
