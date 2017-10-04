k8s-athenz-identity
==========

Control plane components to securely provide [Athenz](https://github.com/yahoo/athenz) identities to 
[Kubernetes](https://kubernetes.io/) application  workloads. See the [launch flow doc](launch-flow.md) for a detailed 
description of the end to end flow.

Works on k8s version 1.8 or above.

Components
----

Note: `sia` is jargon for "Service Identity Agent".

| Name | Description |
| ---- | ----------- |
| athenz-initializer | k8s initializer that watches pods and injects containers with identity documents into pod specs |
| athenz-callback | implements the provider callback endpoint for Athenz |
| athenz-sia | container that knows how to unpack identity information and request credentials from Athenz |
| athenz-control-sia | container that can retrieve TLS certs from Athenz using its own service key (control plane bootstrap) |

Also includes an insecure mock implementation of relevant Athenz APIs for local testing, as well as a test app.

Build
-----

```
$ mkdir -p ${GOPATH}/src/github.com/yahoo
$ cd ${GOPATH}/src/github.com/yahoo
$ git clone <this-repo>
$ cd k8s-athenz-identity
$ make
```

Discussion points
----

* Identity doc in plaintext as environment variable. Discuss implications.
* High-availability of initializer using leader election. Pod launches will be blocked if initializer fails.
* Handling replay attacks for callback endpoint
* Pod IP is not validated. Athenz team looking at enhancing callback to include client IP and SAN IPs requested in the CSR
  as attributes in the extra bag of data given to provider. Ticket: ATHENS-3546

TODOs
----

* Ordering of initializer configuration and deployment of initializer still matters. Will be an upgrade issue. Investigate.
* Dynamic refresh intervals for both control and data plane SIA
* Deployment strategy for provider callback in the face of network ACLs etc.
* Mutual TLS on callback to ensure caller is Athenz
* Add PodIP to SAN for the CSR
