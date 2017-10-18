Components
---

* [Volume driver](#athenz-volume-driver)
* [JWT service](#athenz-jwt-service)
* [Identity agent](#athenz-identity-agent)
* [Athenz initializer](#athenz-initializer)
* [Athenz callback](#athenz-callback)
* [Athenz data plane SIA](#athenz-sia)
* [Athenz control plane SIA](#athenz-control-sia)

### athenz-volume-driver

**Description**: A flex volume driver that creates volumes using which the identity agent socket can be accessed
from containers in a pod.

It supports the `init`, `mount` and `unmount` commands. It is deployed on every host by the identity agent. The binary
is packaged in the identity agent's image and copied to a host path when the agent starts on a node.

Inputs:

* The host path of the directory under which mount volumes are created (`/var/athenz/volumes`, hardcoded for now)
* The host path of the directory containing the agent socket (`/var/athenz/agent`, hardcoded for now)
* Mount inputs: pod metadata (we use only `namespace` and `name`) and the target mount path for the flex volume

Outputs:
* A directory tree containing an opaque pod id and a subdirectory containing the agent socket.

Mount Processing:

* Compute the SHA256 sum of the target volume. The SHA provides a "safe name" (i.e. one not containing directory paths)
  and has the side-effect of being an unguessable string.

* Create the following filesystem under the host volume root

```
   /var/athenz/volumes
     + volume-root     <- SHA256 hash of mount-path
        - data.json    <- contains pod attributes, not visible inside pod
        + mount        <- the directory that is mounted to path
          + connect    <- bind mount of agent directory containing host socket
          - id         <- file containing the mount path hash to be used by pod client as identifier
```

* Bind mount `volume-root/mount` as the mount path using a recursive bind (for the agent socket directory to be 
visible)

* The interface to the pod is: use contents of the `id` file as a proxy for pod identity and request an identity
 by connecting to `agent.sock` under the `connect` sub-directory.

* The identity agent is itself free to store transient state directly under the `volume-root` while keeping this
  invisible from the pod itself.

* Keys, certs etc. are **not** copied anywhere in this directory tree. 

### athenz-jwt-service

**Description**: Signing service to turn pod attributes into a JWT. Run with a control-plane identity with
TLS key and cert. Only accepts requests from the identity-agent using mutual TLS.

Config:
* Private key directory for signing

Inputs: 
* A pod subject to sign

Outputs:
* JWT

### athenz-identity-agent

**Description**: A service on every host exposed via a Unix domain socket that mints and refreshes identities 
for pods created on the same host. Deployed as a daemonset. The pod is also responsible for copying the 
volume driver to the host on startup.

Config:
* ZTS endpoint
* JWT service endpoint
* Pod metadata endpoint (kubelet read API)
* TLS key/cert (node service identity)

Inputs:
* Opaque pod identifier for init and refresh (see volume driver for details)
* Previous key and cert PEM for refresh

Outputs:
* KeyPEM
* CertPEM
* Principal Token

Processing:

Init:
* Turn the input pod id into a filesystem path and load pod metadata created by the volume driver
* Get pod attributes from kubelet endpoint
* Lookup DNS to find the service IP if one exists
* Create a JWT using the signing service
* Generate a private key and associated CSR
* Contact ZTS with the JWT and CSR and get cert/ token
* Write additional state for refresh to the volume filesystem
* Return this information to the caller

Refresh:
* Turn the input pod id into a filesystem path and load refresh state from the volume filesystem
* Contact ZTS for refresh using the previous key and cert supplied by the caller in the client TLS config
* Return refreshed information to the caller

### athenz-initializer

**Description**: A Kubernetes initializer that injects SIA containers and flex volumes into pod definitions.

Config:
* templates of volume mounts and containers to inject
* cluster API credentials

Inputs:
* None

Processing:
* Watch for uninitialized pods using the watch API
* Inject flex volume and containers, mark pod as initialized

### athenz-callback

**Description**: The provider callback that verifies information about the pod that needs an identity. Run as a service
on the cluster using a TLS identity minted by the control-plane SIA.

Config:
* TLS key and cert file
* Directory containing public keys for verifying JWTs

Inputs:
* JWT and attributes provided by Athenz

Outputs:
* Yes to allow launch, No otherwise

Processing:
* Only allow requests from Athenz using mutual TLS
* Verify JWT using public keys
* Verify pod subject using k8s API to get the pod and service (optional)
* Verify DNS, IP and URI SAN names requested
* Grant access

### athenz-sia

**Description**: The service identity agent for data plane workloads.

Config:
* Path to file containing hashed-id of volume
* Socket endpoint for agent socket

Inputs:
* mode: one of "init" or "refresh"

Processing:

* Load opaque id from file
* Contact appropriate endpoint on the agent socket passing in the opaque id
* Write key, cert and token to filesystem
* Loop on refresh, exit on init

### athenz-control-sia

**Description**: The service identity agent for workloads that cannot be given an identity using
standard means since they themselves support the identity workflow.

Config:
* Path to directory containing service key and version files

Inputs:
* mode: one of "init" or "refresh"
* domain/ service of pod

Processing:

* Load private key and version from file
* Generate CSR using this private key 
* Contact ZTS and get cert and token
* Write cert and token to filesystem
* Loop on refresh, exit on init

