#### Thank you for your interest in the K8s Athenz projects! 

### About Athenz
[Athenz](https://www.athenz.io/) is an IAM provider which allows users to define
role based access control (RBAC) for users and services. It also acts as a certificate
authority (CA) by provisioning instances with unique identities through X.509 certificates.

This k8s Athenz project serves to integrate [Athenz](https://github.com/athenz) with [Kubernetes](https://kubernetes.io/) and has several pieces to it. 
Four of the repositories have open issues to be worked on for this event. 

# [k8s-athenz-identity](https://github.com/yahoo/k8s-athenz-identity)
k8s-athenz-identity is a [Kubernetes](https://kubernetes.io/) control plane component
which aims to securely provision unique [Athenz](https://github.com/athenz)
identities (X.509 certificates) for pods.

## Background
Kubernetes provides a mechanism for pods to obtain bound service account JWTs issued
by the API server. However, this JWT is not directly useful outside the Kubernetes
cluster. In general, applications require credentials issued by an organization specific
IAM provider to authenticate with external systems. This project aims to provide a way
for pods to exchange service account JWTs with a credential provider for a unique identity.


# [K8s-athenz-istio-auth](https://github.com/yahoo/k8s-athenz-istio-auth)
K8s-athenz-istio-auth is a controller which converts Athenz domains to Istio RBAC custom resources.

## Background
In order to adopt Athenz as an unified RBAC provider for managing access to Kubernetes
services, we needed a controller that can dynamically fetch Athenz role / policy mappings
and convert them to their corresponding Istio custom resources, so we built this
controller to allow users to define RBAC through Athenz and have it integrate with
the Istio world.

# [k8s-athenz-syncer](https://github.com/yahoo/k8s-athenz-syncer)

K8s-athenz-syncer is a controller that synchronizes the [Athenz](https://athenz.io) domain data including the roles, services and policies
into corresponding Kubernetes [AthenzDomain](https://github.com/yahoo/k8s-athenz-istio-auth/tree/master/pkg) custom resources.

## Background
Athenz is a generic RBAC provider for Kubernetes resource access management and Istio service-service
authentication and authorization. An Athenz domain contains a set of roles and policies defined by service admins. The policies can grant or deny an Athenz role with permissions to perform specific actions on services or resources. An Athenz role can comprise of a set of principals which could represent end users or other services.

Every Kubernetes namespace is mapped to an Athenz domain and the Athenz roles and policies
defined within each domain are used to express access control rules to Kubernetes resources such as deployments,
services, ingresses, etc. associated with the namespace.

# [k8s-athenz-webhook](https://github.com/yahoo/k8s-athenz-webhook)

An API for a Kubernetes authentication and authorization webhook that integrates with
[Athenz](https://github.com/athenz) for access checks. It allows flexible
resource mapping from Kubernetes resources to Athenz.




