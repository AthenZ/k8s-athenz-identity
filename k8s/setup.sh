#!/bin/bash

set -e

NS=kube-system
UNS=default

# first create the mock-athenz service so we can get the cluster IP

kubectl --namespace=${NS} apply -f services/mock-athenz.yaml

mock_athenz_service=mock-athenz.${NS}
mock_athenz_ip=$(kubectl --namespace=kube-system get service mock-athenz -o jsonpath='{.spec.clusterIP}')
mock_athenz_url="http://${mock_athenz_ip}"

# create root CA information and stuff into secret
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
DNS.2   = ${mock_athenz_ip}
EOF
    openssl genrsa -out athenz-ca.pem 2048
    openssl req -key athenz-ca.pem -config /tmp/san.cnf -sha256 -out /tmp/sslcert.csr -new
    openssl req -noout -text -in /tmp/sslcert.csr | grep -e 'Subject:' -e 'DNS:'
    openssl x509 -req -in /tmp/sslcert.csr -extensions req_ext -signkey athenz-ca.pem -days 730 -out athenz-ca.pub.pem
    rm -f /tmp/san.cnf /tmp/sslcert.csr
    kubectl --namespace=${NS} create secret generic mock-athenz-root-ca \
        --from-literal="key=`cat athenz-ca.pem`" \
        --from-literal="cert=`cat athenz-ca.pub.pem`"
fi

# create initializer identity
if [[ ! -f identity.pem ]]
then
    openssl genrsa -out identity.pem 2048
    openssl rsa -in identity.pem -outform PEM -pubout -out identity.pub.pem
    kubectl --namespace=${NS} create secret generic athenz-initializer-identity --from-literal="service.key=`cat identity.pem`" --from-literal="service.version=v1"
fi

# create signing keys
if [[ ! -f signing.pem ]]
then
    openssl genrsa -out signing.pem 2048
    openssl rsa -in signing.pem -outform PEM -pubout -out signing.pub.pem
    kubectl --namespace=${NS} create secret generic athenz-initializer-public --from-literal="signing.v1=`cat signing.pub.pem`"
    kubectl --namespace=${NS} create secret generic athenz-initializer-private --from-literal="signing.v1=`cat signing.pem`"
fi

# create the remaining objects
kubectl --namespace=${NS} apply -f rbac.yaml
kubectl --namespace=${NS} apply -f configmaps/athenz-initializer.yaml
kubectl --namespace=${NS} apply -f deployments/mock-athenz.yaml
kubectl --namespace=${NS} apply -f deployments/athenz-initializer.yaml
kubectl --namespace=${NS} apply -f deployments/athenz-callback.yaml
kubectl --namespace=${NS} apply -f services/athenz-callback.yaml
kubectl --namespace=${NS} apply -f initializer-configurations/athenz-initializer.yaml

kubectl --namespace=${UNS} apply -f app/service-account.yaml
kubectl --namespace=${UNS} apply -f app/test-app-pod.yaml

