k8s-athenz-identity
==========

Proof of concept control plane components to securely provide [Athenz](https://github.com/yahoo/athenz) identities to 
[Kubernetes](https://kubernetes.io/) application workloads. 

See the [design document](DESIGN.md) for a detailed description of the end to end flow. 
Read the [components doc](COMPONENTS.md) for details on every component.

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

Testing
-----

For my tests, I have set up a single node k8s cluster on a bare-metal box. Cluster created using kubeadm with
the `Noschedule` taint removed from the master and extra alpha flags for new features for the API.

There is a one command `setup` and `teardown` in the `k8s` folder that do everything. 
Your mileage in getting this to work may vary :)

In any case, you can see all the moving parts by inspecting the [setup script](k8s/setup.sh) and all the YAML files
for the configmaps, deployments and daemonsets.

TODOs
----

* High-availability of initializer using leader election.
* Admission controller that enforces initializer for user apps, does not allow random workloads to use the custom volume driver etc.
* Ordering of initializer configuration and deployment of initializer still matters. Will be an upgrade issue. Investigate.
* Dynamic refresh intervals for both control and data plane SIA
