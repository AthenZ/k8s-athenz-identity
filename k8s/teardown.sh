#!/bin/bash

SNS=kube-system

kubectl delete -f namespaces/user-apps.yaml
kubectl delete -f namespaces/k8s-admin.yaml

kubectl --namespace=${SNS} delete -f initializer-configurations/athenz-initializer.yaml
kubectl --namespace=${SNS} delete -f rbac.yaml

rm -f *pem
rm -rf node-keys/
