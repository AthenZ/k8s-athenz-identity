design
===

### Athenz overview

* Athenz is an athentication/ authorization system. Authorization is based on RBAC.
* It has the concept of domains (namespaces), roles, policies, principals and services.
  * A domain roughly maps to a Kubernetes namespace, except for naming convention. Domains typically have dots
    (e.g. `media.sports`) while K8s namespaces do not.
  * Domains can appear to be hierarchical but they are not. Every domain is a self-contained entity. The only place where
    hierarchy is used is in subdomain create/ delete. The parent domain's admin role has the ability to create and
    delete subdomains. Top-level domains can only be created or deleted by Athenz administrators. 
* Principals may be humans or services. Principals authenticate themselves using principal tokens or TLS certs.
* Service public keys can be uploaded to Athenz for specific key versions. A process that has access to the
  private key can authenticate itself against Athenz by signing its own identity token and get TLS credentials. 
* Athenz also supports the notion of one service launching another. This supports bootstrapping use-cases for bare-metal
  (where openstack is the launcher service for example) as well as multi-tenant use-cases (where Mesos/ Kubernetes 
  is the launcher).
* In this flow, the launcher service can request TLS certs for the launched service. Athenz calls back to a 
  service provider endpoint to ensure it is a valid launch and returns a TLS identity. The service can then use the 
  current credentials to prove its identity and refresh them periodically.
  * Additional safeguards require the launcher service to be part of a whitelist of services that can launch others
    and the launcher service must have explicit access to launch specific services via Athenz policies that are set up
    for each service that is launched.
    
### Athenz and K8s Identities

* A kubernetes and Athenz services map 1:1 with name translation from domain name to k8s namespace. The mapping logic we
  use is simple:
  * Namespaces in K8s are set up as the domain name in Athenz except for literal dashes that are converted to 2 dashes.
    The domain `foo.bar-baz` becomes the namespace `foo-bar--baz`.
  * System namespaces in K8s are turned into a subdomain of the admin Athenz domain for a K8s cluster. For example if the admin
    domain for the cluster is called `k8s.admin`, the `kube-dns` service in the `kube-system` domain will be turned into
    `k8s.admin.kube-system.kube-dns`.
  * The above strategy ensures that names can be mapped unambiguously in both directions.
  * Service names do not need mapping and can be used in both places as-is.
* A Kubernetes pod has a service identity derived from the namespace that it runs in and the service account used to
  launch it. The service account should have the same name as the service that is used to route to pods.
* There is no notion of container identity (yet).

### TLS identities

A TLS cert for an Athenz service has the following characteristics.

* A common name that is the equal to `<athenz-domain><DOT><athenz-service>` (e.g. `media.sports.frontend`)
* 2 SAN names constructed as follows:
    * `<service><DOT><dashed-domain><DOT><dns-suffix>`
    * `<unique-id><DOT>instanceid.athenz<DOT><dns-suffix>`

  where `dns-suffix` is a suffix that is allocated per provider service.
* It may be possible to arrange the DNS suffix and domain transformation such that the `kube-dns` name and the
  SAN name in the Athenz cert match exactly. This option has not been fully explored; the current prototype 
  assumes that the DNS names for the same service will be different across Athenz and K8s.
  * This adds friction for mutual TLS where one service needs to connect to another via the `kube-dns` name and set up
    SNI for the Athenz name.

### Service identity bootstrap

* We assume that every node has ephemeral TLS certs created on boot and refreshed in the background by the provision service
  (e.g. openstack) and a node-agent running on every box. This is outside the scope of kubernetes.
* The k8s identity agent uses these certs to prove its identity.
* Every pod launched on a node is given an identity by the identity agent using the kubelet API as the source of truth.
  * Pods (via init container and sidecars) must request an identity init/ refresh from the local identity agent. The 
    identity agent listens on a Unix domain socket that is mounted into the pod sidecar/ init container via a flex volume.
  * The identity agent in turn collects information about the pod being launched and creates a JWT representing the pod
    identity. 
  * This is forwarded to Athenz which, in turn, calls back on the provider callback endpoint for verification.
  * The provider callback verifies the identity document by comparing it against pod and service information from the 
    K8s API.
* The provider callback is itself a K8s service running on the cluster bootstrapped with an Athenz identity using a
  service key.
* The JWT needs to be signed and verified. There are no keys on the box that can be used to sign documents. This requires
  a signing service that has been loaded with private keys. The corresponding public keys are loaded into the 
  provider callback for verifying JWTs. The identity agent uses the signing service to sign JWTs.
* Mutual TLS ensures that only the components that can allowed to talk to each other can in fact do so.

### Identity document

The identity document is a JWT that looks as follows:

#### Header

```json
{
  "alg": "RS256",
  "iss": "secret:athens-init-secret?version=v1",
  "typ": "JWT"
}
```

#### Payload

```json
{
  "aud": "k8s-athenz-identity",
  "exp": 1507101919,
  "iat": 1507101019,
  "iss": "secret:athens-init-secret?version=v1",
  "sub": "pod:k8s-namespace/k8s-pod-id?d=athenz-domain&n=athenz-service&i=pod-ip&s=service-ip"
}
```

### Launch flow

![sequence diagram](sequence.png)

