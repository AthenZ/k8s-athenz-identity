### Athenz overview

The long version can be found [here](https://github.com/yahoo/athenz).

> Athenz is a role-based authorization (RBAC) system for provisioning and configuration (centralized authorization) 
> use cases as well as serving/runtime (decentralized authorization) use cases"

* Athenz is an athentication/ authorization system. Authorization is based on RBAC.
* It has the concept of [domains (namespaces), roles, policies, principals and services](https://github.com/yahoo/athenz/blob/master/docs/data_model.md#data-model).
  * A domain roughly maps to a Kubernetes namespace, except for naming convention. Domains typically have dots
    (e.g. `media.sports`) while K8s namespaces do not.
  * Domains can appear to be hierarchical but they are not. Every domain is a self-contained entity. The only place where
    hierarchy is used is in subdomain create/ delete. The parent domain's admin role has the ability to create and
    delete subdomains. Top-level domains can only be created or deleted by Athenz administrators. 
* Principals may be humans or services. Principals authenticate themselves using principal tokens or TLS certs.
* Service public keys can be uploaded to Athenz for specific key versions. A process that has access to the
  private key can authenticate itself against Athenz by signing its own identity token and exchanging it for TLS credentials. 
* Athenz also supports the notion of one service launching another. This supports bootstrapping use-cases for bare-metal
  (where openstack is the launcher service for example) as well as multi-tenant use-cases (where Mesos/ Kubernetes 
  is the launcher).
* In this flow, the launcher service can request TLS certs for the launched service. Athenz calls back to a 
  service provider endpoint to ensure it is a valid launch and returns a TLS identity. The service can then use the 
  these credentials to prove its identity and refresh them periodically.
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
* There is no notion of container identity.

### TLS identities

A TLS cert for an Athenz service has the following characteristics.

* A common name that is the equal to `<athenz-domain><DOT><athenz-service>` (e.g. `media.sports.frontend`)
* 2 DNS SAN names constructed as follows:
    * `<service><DOT><mangled-domain><DOT><dns-suffix>`
    * `<unique-id><DOT>instanceid.athenz<DOT><dns-suffix>`

  where `dns-suffix` is a suffix that is allocated per provider service. This should be arranged to be the same
  as the DNS suffix used for kube-dns for the cluster. `mangled-domain` is the domain with dots replaced with
  dashes and literal dashes turned into double dashes.
* SAN IP for pod IP 
* Proposed: SPIFFE URI as SAN name, not yet implemented.

