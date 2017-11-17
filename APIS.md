## APIs

### Athenz (ZTS)

#### Exchange CSR for TLS cert

A service that possesses its own private key can get a TLS cert from Athenz corresponding to its private key.

```
POST "/instance/my.domain/the-service/refresh"
```

Input:
```json
{
    "csr": "PEM-encoded CSR",
    "keyId": "v1"
}
```

The CSR should be signed by the private key for the supplied key-version where the public key has been uploaded
to Athenz.

Output:
```json
{
    "name": "my.domain.the-service",
    "certificate": "PEM encoded cert",
    "caCertBundle": "PEM encoded root CA bundle"
}
```

#### Get tokens and TLS certs using launcher service
This call allows a launcher service to attest to the calling service's identity.
```
POST "/instance"
```

Input:
```json
{
    "provider": "provider.domain.launcher-service",
    "domain": "my.domain",
    "service": "the-service",
    "attestationData": "JWT",
    "csr": "PEM-encoded CSR",
    "token": true
}
```

Output:
```json
{
    "name": "my.domain.the-service",
    "certificate": "PEM encoded cert",
    "caCertBundle": "PEM encoded root CA bundle",
    "signedToken": "signed principal token"
}
```

### Provider callback
Athenz calls back to the launcher service to verify the requested identity. The launcher service is discovered
using the endpoint registered for it in Athenz. Athenz will only trust the callback endpoint if it's TLS cert
has been minted using the Athenz root CA and has the expected common name.

```
POST "/instance"
```
Input:
```json
{
    "provider": "provider.domain.launcher-service",
    "domain": "my.domain",
    "service": "the-service",
    "attestationData": "JWT",
    "attributes": {
      "sanDNS": "name1,name2",
      "sanIP": "ip1,ip2",
      "clientIP": "ip"
    }
}
```

Output:
Returns the same object with a 200 response if identity should be granted.

### Identity agent

#### Get initial identity

```
POST /init/OPAQUE-ID
```
No inputs.

Output
```json
{
	"ntoken": "signed principal token",
	"keyPEM": "PEM-encoded key",
	"certPEM": "PEM-encoded cert",
	"caCertPEM": "PEM encoded rootCA bundle"
}
```

#### Refresh identity using prior credentials

```
POST /refresh/OPAQUE-ID
```

Input:
```json
{
	"keyPEM": "PEM-encoded key",
	"certPEM": "PEM-encoded cert"
}
```

Output:
```json
{
	"ntoken": "signed principal token",
	"keyPEM": "PEM-encoded key",
	"certPEM": "PEM-encoded cert",
	"caCertPEM": "PEM encoded rootCA bundle"
}
```
