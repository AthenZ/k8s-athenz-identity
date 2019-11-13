# K8s-athenz-identity
K8s-athenz-identity is a control plane component which aims to securely provision unique
[Athenz](https://github.com/yahoo/athenz) identities for [Kubernetes](https://kubernetes.io/)
pods.

## Background
Due to Kubernetes itself not providing a mechanism to provision unique identities per
application pods, the need arose to create a control plane components which fulfills
this use case.

### Athenz
Athenz is an IAM provider which allows users to define role based access control
(RBAC) for users and services. It also acts as a certificate authority (CA) by
provisioning instances with unique identities through X.509 certificates.

More information can be found on their official [website](https://www.athenz.io/).

### Copper Argos
Copper Argos provides identity provisioning systems with a callback provider
concept which acts as an extra security layer to validate that the instances
being provisioned are allowed to receive the requested identity.

More information can be found on the Athenz website [here](https://yahoo.github.io/athenz/site/copper_argos_dev/)

## Architecture
The architecture sections dives into the details of the various components built
to create a Copper Argos identity provider.

![Screenshot](docs/images/architecture.png)

### SIA
Service Identity Agent (SIA) is a container which is bundled as a sidecar for a
pod. It is primarily responsible for creating a CSR for the application workload
and requesting a certificate from Athenz ZTS. SIA is mounted with a bound Kubernetes
service account JWT issued with an audience specific to the identity provider,
“athenz-identityd” (can be Athenz service of identity provider).

These are the steps the SIA container follows to retrieve an identity:
1. Creates a new private key and signs a CSR with the subject common name as
“<athenz-domain>.<athenz-service>”, required SANs, etc.
2. Constructs an Athenz InstanceRegisterInformation object with the CSR and the
bound service account JWT as attestation data
3. Makes a request to ZTS for the postInstanceRegister API call.
4. ZTS forwards the attestation data and CSR details to the identity provider
for validation
5. Certificate is minted and returned to the SIA container

### Identityd
Identity provider is an Athenz Copper Argos callback provider which validates
requests for new identities. It runs as a deployment in the cluster and has an
in-memory cache of all running pods.

There are the steps the Identity provider follows to validate an identity:
1. Validate the bound service account JWT of the attestation data is valid, this
involves either making a request to the Kubernetes API or using public key validation.
2. Validate a pod which is requesting the identity is actually running within the
cluster.
3. Validate the CSR details including IP, SANS, common name, etc.

#### OPA


## Getting Started

### Pre-requisities
There are a variety of prerequisites required in order to run this identity provider,
they are specified below.
- **Kubernetes cluster** - A running Kubernetes cluster is required with access to
the control plane. More information on how to setup a cluster can be found in the
official documentation [here](https://kubernetes.io/docs/setup/).
- **Athenz** - Athenz must be fully deployed in order to setup this identity provider
as an Copper Argos callback endpoint. More information and setup steps can be found
[here](http://www.athenz.io/).

### Configuration

### Usage

## Troubleshooting

### Monitoring

## Contribute
Please refer to the [contributing](Contributing.md) file for information about
how to get involved. We welcome issues, questions, and pull requests.

## Maintainers/Contacts
Core Team : omega-core@verizonmedia.com

## License
Copyright 2019 Verizon Media Inc. Licensed under the terms of the 3-Clause BSD License.

