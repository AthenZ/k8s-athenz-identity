#!/bin/bash

SNS=kube-system

kubectl delete -f namespaces/user-apps.yaml
kubectl delete -f namespaces/k8s-admin.yaml

kubectl --namespace=${SNS} delete -f deployments/mock-athenz.yaml
kubectl --namespace=${SNS} delete -f initializer-configurations/athenz-initializer.yaml
kubectl --namespace=${SNS} delete -f services/mock-athenz.yaml
kubectl --namespace=${SNS} delete secret mock-athenz-tls
kubectl --namespace=${SNS} delete secret mock-athenz-root-ca
kubectl --namespace=${SNS} delete -f rbac.yaml

rm -f *pem
rm -rf node-keys/
