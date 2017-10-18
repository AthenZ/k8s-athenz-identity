k8s-athenz-identity
==========

Control plane components to securely provide [Athenz](https://github.com/yahoo/athenz) identities to 
[Kubernetes](https://kubernetes.io/) application workloads. See the [design document](DESIGN.md) for a detailed 
description of the end to end flow. Read the [components doc](COMPONENTS.md) for details on every component.

Works on k8s version 1.8 or above.

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

* High-availability of initializer using leader election. Pod launches will be blocked if initializer fails.
* Handling replay attacks for identity/ callback endpoint
* Pod IP is not validated against SANS IPs requested for certificate. Athenz team looking at enhancing callback to 
  include client IP and SAN IPs requested in the CSR as attributes in the extra bag of data given to provider. Ticket: ATHENS-3546

TODOs
----

* Admission controller that enforces initializer for user apps, does not allow random workloads to use the custom volume driver etc.
* Ordering of initializer configuration and deployment of initializer still matters. Will be an upgrade issue. Investigate.
* Dynamic refresh intervals for both control and data plane SIA
* Deployment strategy for provider callback in the face of network ACLs etc.
