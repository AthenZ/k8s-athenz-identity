## APIs

### Athenz (ZTS)

Athenz provides 2 mechanisms for services to get an identity, one by proving key ownership and the other
when launched using a provider (openstack, AWS, mesos, kubernetes etc.)

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
A service being launched by another can get an identity using an identity document that the launcher validates
on Athenz's behalf. The CSR is signed using an ephemeral private key.

```
POST "/instance"
```

Input:
```json
{
    "provider": "provider.domain.launcher-service",
    "domain": "my.domain",
    "service": "the-service",
    "attestationData": "JWT or some other format",
    "csr": "PEM-encoded CSR",
    "token": true
}
```

Output:
```json
{
    "provider": "provider.domain.launcher-service",
    "name": "my.domain.the-service",
    "instanceId": "athenz-generated-id",
    "x509Certificate": "PEM encoded cert",
    "x509CertificateSigner": "PEM encoded root CA bundle",
    "serviceToken": "signed principal token",
    "attributes": {}
}
```

#### Refresh an identity returned in a previous call

After the initial identity is gotten, it may be used as proof for refreshes. The refresh request must be posted
using a client with certificates for the previous identity.

```
POST /instance/provider.domain.launcher-service/my.domain/the-service/instance-id
```

Input:
```json
{
    "csr": "PEM-encoded CSR",
    "token": true
}
```

Output:
```json
{
    "provider": "provider.domain.launcher-service",
    "name": "my.domain.the-service",
    "instanceId": "athenz-generated-id",
    "x509Certificate": "PEM encoded cert",
    "x509CertificateSigner": "PEM encoded root CA bundle",
    "serviceToken": "signed principal token",
    "attributes": {}
}
```

### Provider callback
Athenz calls back to the launcher service to verify the requested identity. The launcher service is discovered
using the endpoint registered for it in Athenz. Athenz will only trust the callback endpoint if its TLS cert
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
Returns the same object with a 200 response, with possibly additional attributes, if the identity should be granted.

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
