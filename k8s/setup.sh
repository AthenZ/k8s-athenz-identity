#!/bin/bash

set -e

section() {
    echo "======================================================================"
    echo "$@"
    echo "======================================================================"
}

SNS=kube-system
NS=k8s-admin
UNS=user-apps

section "Setup base paths on node"

# This stuff is not yet configurable, must be the correct paths

if [[ -d /usr/libexec/kubernetes/kubelet-plugins/volume/exec/athenz.kubernetes.io~athenz-volume-driver/ ]]
then
    sudo mkdir -p /usr/libexec/kubernetes/kubelet-plugins/volume/exec/athenz.kubernetes.io~athenz-volume-driver/
fi
if [[ ! -d /var/athenz/agent ]]
then
    sudo mkdir -p /var/athenz/agent
fi
if [[ ! -d /var/athenz/driver ]]
then
    sudo mkdir -p /var/athenz/driver
fi
if [[ ! -d /var/athenz/node/identity ]]
then
    sudo mkdir -p /var/athenz/node/identity
fi

section "Create namespaces"
kubectl apply -f namespaces/k8s-admin.yaml
kubectl apply -f namespaces/user-apps.yaml

section "Setup RBAC"

# setup RBAC
kubectl --namespace=${NS} apply -f rbac-admin.yaml
kubectl --namespace=${SNS} apply -f rbac.yaml

section "Setup mock-athenz"

# first create the mock-athenz service so we can get the cluster IP
kubectl --namespace=${SNS} apply -f services/mock-athenz.yaml

mock_athenz_service=mock-athenz.${SNS}.svc.cluster.local
mock_athenz_ip=$(kubectl --namespace=${SNS} get service mock-athenz -o jsonpath='{.spec.clusterIP}')
mock_athenz_url="https://${mock_athenz_ip}"

# create a specific root CA for the Athenz service itself, distinct from the root CA for workloads
if [[ ! -f athenz-ca.pem ]]
then
    cat <<EOF >/tmp/san.cnf
[ req ]
default_bits       = 2048
distinguished_name = dn
req_extensions     = ext
prompt             = no

[ dn ]
commonName                 = ${mock_athenz_service}
countryName                = US
stateOrProvinceName        = California
localityName               = Sunnyvale
organizationName           = Acme

[ ext ]
subjectAltName = @alt_names

[alt_names]
DNS.1   = ${mock_athenz_service}
IP.1   = ${mock_athenz_ip}
EOF
    openssl genrsa -out athenz-ca.pem 2048
    openssl req -key athenz-ca.pem -config /tmp/san.cnf -sha256 -out /tmp/sslcert.csr -new
    openssl x509 -req -in /tmp/sslcert.csr -extfile /tmp/san.cnf -extensions ext -signkey athenz-ca.pem -days 730 -out athenz-ca.pub.pem
    openssl x509 -noout -text < athenz-ca.pub.pem
    rm -f /tmp/san.cnf /tmp/sslcert.csr
    kubectl --namespace=${SNS} create secret generic mock-athenz-tls \
        --from-literal="server.key=`cat athenz-ca.pem`" \
        --from-literal="server.cert=`cat athenz-ca.pub.pem`"
fi

# create the root CA for workloads used by the mock Athenz service
if [[ ! -f athenz-root-ca.pem ]]
then
    cat <<EOF >/tmp/san.cnf
[ req ]
default_bits       = 2048
distinguished_name = dn
prompt             = no

[ dn ]
commonName                 = Athenz
countryName                = US
stateOrProvinceName        = California
localityName               = Sunnyvale
organizationName           = Acme
EOF
    openssl genrsa -out athenz-root-ca.pem 2048
    openssl req -key athenz-root-ca.pem -config /tmp/san.cnf -sha256 -out /tmp/sslcert.csr -new
    openssl x509 -req -in /tmp/sslcert.csr -signkey athenz-root-ca.pem -days 730 -out athenz-root-ca.pub.pem
    openssl x509 -noout -text < athenz-root-ca.pub.pem
    rm -f /tmp/san.cnf /tmp/sslcert.csr
    kubectl --namespace=${SNS} create secret generic mock-athenz-root-ca \
        --from-literal="key=`cat athenz-root-ca.pem`" \
        --from-literal="cert=`cat athenz-root-ca.pub.pem`"
fi

kubectl --namespace=${SNS} apply -f deployments/mock-athenz.yaml

section Setup athenz config map
athenz-write-config >/tmp/cluster.yaml
athenz-write-config --wrap | kubectl --namespace=${NS} apply -f -

section "Create signing keys"
if [[ ! -f signing.pem ]]
then
    openssl genrsa -out signing.pem 2048
    openssl rsa -in signing.pem -outform PEM -pubout -out signing.pub.pem
    kubectl --namespace=${NS} create secret generic athenz-signing-public --from-literal="signing.v1=`cat signing.pub.pem`"
    kubectl --namespace=${NS} create secret generic athenz-signing-private --from-literal="signing.v1=`cat signing.pem`"
fi

section "Setup node keys using athenz-control-sia"
echo "****" This can fail if basic services are not yet up. Just re-run the script if this happens "****"

if [[ ! -f node-keys/service.cert ]]
then
    mkdir -p ./node-keys
    openssl genrsa -out node-keys/service.key 2048
    echo -n v1> node-keys/service.version
    athenz-control-sia --mode=init --dns-suffix=example.cloud  \
        --namespace=k8s-admin --account=k8s-node --endpoint https://${mock_athenz_ip}/zts/v1 \
        --out-ntoken=node-keys/token --out-cert=node-keys/service.cert --out-ca-cert=node-keys/ca.cert \
        --identity-dir=./node-keys/ --config /tmp/cluster.yaml
    sudo cp node-keys/service.key /var/athenz/node/identity/service.key
    sudo cp node-keys/service.cert /var/athenz/node/identity/service.cert
    sudo cp node-keys/ca.cert /var/athenz/node/identity/ca.cert
fi

section "Setup JWT service"

kubectl --namespace=${NS} apply -f services/athenz-jwt-service.yaml

# create jwt-service identity
if [[ ! -f jwt-service.pem ]]
then
    openssl genrsa -out jwt-service.pem 2048
    openssl rsa -in jwt-service.pem -outform PEM -pubout -out jwt-service.pub.pem
    kubectl --namespace=${NS} create secret generic athenz-jwt-service-identity --from-literal="service.key=`cat jwt-service.pem`" --from-literal="service.version=v1"
fi

kubectl --namespace=${NS} apply -f deployments/athenz-jwt-service.yaml

section "Setup identity agent"
kubectl --namespace=${NS} apply -f daemonsets/athenz-identity-agent.yaml

section Setup initializer
kubectl --namespace=${NS} apply -f configmaps/athenz-initializer.yaml
kubectl --namespace=${NS} apply -f deployments/athenz-initializer.yaml

kubectl --namespace=${SNS} apply -f initializer-configurations/athenz-initializer.yaml

kubectl --namespace=${UNS} apply -f app/service-account.yaml
#### kubectl --namespace=${UNS} apply -f app/test-app-pod.yaml

exit 0


# create the remaining objects
kubectl --namespace=${NS} apply -f deployments/athenz-callback.yaml
kubectl --namespace=${NS} apply -f services/athenz-callback.yaml


