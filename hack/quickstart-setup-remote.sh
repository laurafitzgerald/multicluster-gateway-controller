#!/bin/bash

#
# Copyright 2022 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_SETUP_DIR="$(dirname "${BASH_SOURCE[0]}")"

# shellcheck shell=bash
### This section is copied from ./setupEnv for script install, if you update this please also update the file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/../bin"


export KIND_BIN=kind
export YQ_BIN=yq
export ISTIOCTL_BIN="${BIN_DIR}/istioctl"
export OPERATOR_SDK_BIN="${BIN_DIR}/operator-sdk"
export CLUSTERADM_BIN="${BIN_DIR}/clusteradm"
export SUBCTL_BIN="${BIN_DIR}/subctl"

source /dev/stdin <<< "$(curl -s https://raw.githubusercontent.com/Kuadrant/multicluster-gateway-controller/main/hack/.kindUtils)"
source /dev/stdin <<< "$(curl -s https://raw.githubusercontent.com/Kuadrant/multicluster-gateway-controller/main/hack/.clusterUtils)"
source /dev/stdin <<< "$(curl -s https://raw.githubusercontent.com/Kuadrant/multicluster-gateway-controller/main/hack/.cleanupUtils)"

MGC_REPO="https://github.com/Kuadrant/multicluster-gateway-controller.git/"


KIND_CLUSTER_PREFIX="mgc-"
KIND_CLUSTER_CONTROL_PLANE="${KIND_CLUSTER_PREFIX}control-plane"
KIND_CLUSTER_WORKLOAD="${KIND_CLUSTER_PREFIX}workload"

INGRESS_NGINX_KUSTOMIZATION_DIR=${MGC_REPO}/config/ingress-nginx
METALLB_KUSTOMIZATION_DIR=${MGC_REPO}/config/metallb
CERT_MANAGER_KUSTOMIZATION_DIR=${MGC_REPO}/config/cert-manager
EXTERNAL_DNS_KUSTOMIZATION_DIR=${MGC_REPO}/config/external-dns
# TODO: use remote file with kubectl
ISTIO_KUSTOMIZATION_DIR=${LOCAL_SETUP_DIR}/../config/istio/istio-operator.yaml
GATEWAY_API_KUSTOMIZATION_DIR=${MGC_REPO}/config/gateway-api

# TODO: Is this used?
TLS_CERT_PATH=${LOCAL_SETUP_DIR}/../config/webhook-setup/control/tls

set -e pipefail

deployIngressController () {
  clusterName=${1}
  kubectl config use-context kind-${clusterName}
  echo "Deploying Ingress controller to ${clusterName}"
  kustomize build ${INGRESS_NGINX_KUSTOMIZATION_DIR} --enable-helm --helm-command helm | kubectl apply -f -
  echo "Waiting for deployments to be ready ..."
  kubectl -n ingress-nginx wait --timeout=600s --for=condition=Available deployments --all
}

deployMetalLB () {
  clusterName=${1}
  metalLBSubnet=${2}

  kubectl config use-context kind-${clusterName}
  echo "Deploying MetalLB to ${clusterName}"
  kustomize build ${METALLB_KUSTOMIZATION_DIR} | kubectl apply -f -
  echo "Waiting for deployments to be ready ..."
  kubectl -n metallb-system wait --for=condition=ready pod --selector=app=metallb --timeout=300s
  echo "Creating MetalLB AddressPool"
  cat <<EOF | kubectl apply -f -
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: example
  namespace: metallb-system
spec:
  addresses:
  - 172.32.${metalLBSubnet}.0/24
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
EOF
}

deployCertManager() {
  clusterName=${1}
  echo "Deploying Cert Manager to (${clusterName})"

  kubectl config use-context kind-${clusterName}

  kustomize build ${CERT_MANAGER_KUSTOMIZATION_DIR} --enable-helm --helm-command helm | kubectl apply -f -
  echo "Waiting for Cert Manager deployments to be ready..."
  kubectl -n cert-manager wait --timeout=300s --for=condition=Available deployments --all

  kubectl delete validatingWebhookConfiguration mgc-cert-manager-webhook
  kubectl delete mutatingWebhookConfiguration mgc-cert-manager-webhook
  # Apply the default glbc-ca issuer
  cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: glbc-ca
  namespace: cert-manager
spec:
  selfSigned: {}
EOF
}

deployExternalDNS() {
  clusterName=${1}
  echo "Deploying ExternalDNS to (${clusterName})"

  kubectl config use-context kind-${clusterName}

  kustomize build ${EXTERNAL_DNS_KUSTOMIZATION_DIR} --enable-helm --helm-command helm | kubectl apply -f -
  echo "Waiting for External DNS deployments to be ready..."
  kubectl -n external-dns wait --timeout=300s --for=condition=Available deployments --all
}

deployIstio() {
  clusterName=${1}
  echo "Deploying Istio to (${clusterName})"

  kubectl config use-context kind-${clusterName}
  ${ISTIOCTL_BIN} operator init
	kubectl apply -f  ${ISTIO_KUSTOMIZATION_DIR}
}

installGatewayAPI() {
  clusterName=${1}
  kubectl config use-context kind-${clusterName}
  echo "Installing Gateway API in ${clusterName}"

  kustomize build ${GATEWAY_API_KUSTOMIZATION_DIR} | kubectl apply -f -
}

deployOLM(){
  clusterName=${1}
  
  kubectl config use-context kind-${clusterName}
  echo "Installing OLM in ${clusterName}"
  
  ${OPERATOR_SDK_BIN} olm install --timeout 6m0s
}

deployOCMHub(){
  clusterName=${1}
  echo "installing the hub cluster in kind-(${clusterName}) "

  ${CLUSTERADM_BIN} init --bundle-version='0.11.0' --wait --context kind-${clusterName}
  echo "PATCHING CLUSTERMANAGER: placement image patch to use amd64 image - See https://kubernetes.slack.com/archives/C01GE7YSUUF/p1685016272443249"
  kubectl patch clustermanager cluster-manager --type='merge' -p '{"spec":{"placementImagePullSpec":"quay.io/open-cluster-management/placement:v0.11.0-amd64"}}'
  echo "checking if cluster is single or multi"
  if [[ -n "${OCM_SINGLE}" ]]; then
    clusterName=kind-${KIND_CLUSTER_CONTROL_PLANE}
    echo "Found single cluster installing hub and spoke on the one cluster (${clusterName})"
    join=$(${CLUSTERADM_BIN} get token --context ${clusterName} |  grep -o  'clusteradm.*--cluster-name')
    ${BIN_DIR}/${join} ${clusterName} --bundle-version='0.11.0' --feature-gates=RawFeedbackJsonString=true --force-internal-endpoint-lookup --context ${clusterName} | grep clusteradm
    echo "accepting OCM spoke cluster invite"
  
    max_retry=18
    counter=0
    until ${CLUSTERADM_BIN} accept --clusters ${clusterName}
    do
      sleep 10
      [[ counter -eq $max_retry ]] && echo "Failed!" && exit 1
      echo "Trying again. Try #$counter"
      ((++counter))
    done
    deployOLM ${KIND_CLUSTER_CONTROL_PLANE}
    deployIstio ${KIND_CLUSTER_CONTROL_PLANE}
  fi
}

deployOCMSpoke(){
  clusterName=${1}
  echo "joining the spoke cluster to the hub cluster kind-(${KIND_CLUSTER_CONTROL_PLANE}),"
  kubectl config use-context kind-${KIND_CLUSTER_CONTROL_PLANE}
  join=$(${CLUSTERADM_BIN} get token --context kind-${KIND_CLUSTER_CONTROL_PLANE} |  grep -o  'clusteradm.*--cluster-name')
  kubectl config use-context kind-${clusterName}
  ${BIN_DIR}/${join} kind-${clusterName} --bundle-version='0.11.0' --feature-gates=RawFeedbackJsonString=true --force-internal-endpoint-lookup --context kind-${clusterName} | grep clusteradm
  echo "accepting OCM spoke cluster invite"
  kubectl config use-context kind-${KIND_CLUSTER_CONTROL_PLANE}
  
  max_retry=18
  counter=0
  until ${CLUSTERADM_BIN} accept --clusters kind-${clusterName}
  do
     sleep 10
     [[ counter -eq $max_retry ]] && echo "Failed!" && exit 1
     echo "Trying again. Try #$counter"
     ((++counter))
  done

}

initController() {
    clusterName=${1}
    kubectl config use-context kind-${clusterName}
    echo "Initialize local dev setup for the controller on ${clusterName}"

    # Add the mgc CRDs
    kustomize build ${MGC_REPO}/config/crd | kubectl apply -f -

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  labels:
    control-plane: controller-manager
  name: multi-cluster-gateways
EOF

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${KIND_CLUSTER_PREFIX}aws-credentials
type: Opaque
stringData:
  AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID}
  AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}
  AWS_REGION: ${AWS_REGION}
EOF

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${KIND_CLUSTER_PREFIX}controller-config
data:
  AWS_DNS_PUBLIC_ZONE_ID: ${AWS_DNS_PUBLIC_ZONE_ID}
  ZONE_ROOT_DOMAIN: ${ZONE_ROOT_DOMAIN}
  LOG_LEVEL: "${LOG_LEVEL}"
EOF

    cat <<EOF | kubectl apply -f -
apiVersion: kuadrant.io/v1alpha1
kind: ManagedZone
metadata:
  name: ${KIND_CLUSTER_PREFIX}dev-mz
spec:
  id: ${AWS_DNS_PUBLIC_ZONE_ID}
  domainName: ${ZONE_ROOT_DOMAIN}
  description: "Dev Managed Zone"
  dnsProviderSecretRef:
    name: ${KIND_CLUSTER_PREFIX}aws-credentials
    namespace: multi-cluster-gateways
    type: AWS
EOF
}


# Prompt user for any required env vars that have not been set
if [[ -z "${AWS_ACCESS_KEY_ID}" ]]; then
  echo "Enter your AWS access key ID:"
  read AWS_ACCESS_KEY_ID
fi
if [[ -z "${AWS_SECRET_ACCESS_KEY}" ]]; then
  echo "Enter your AWS secret access key:"
  read AWS_SECRET_ACCESS_KEY
fi
if [[ -z "${AWS_REGION}" ]]; then
  echo "Enter an AWS region (e.g. eu-west-1):"
  read AWS_REGION
fi
if [[ -z "${AWS_DNS_PUBLIC_ZONE_ID}" ]]; then
  echo "Enter the Public Zone ID of your Route53 zone:"
  read AWS_DNS_PUBLIC_ZONE_ID
fi
if [[ -z "${ZONE_ROOT_DOMAIN}" ]]; then
  echo "Enter the root domain of your Route53 hosted zone (e.g. www.example.com):"
  read ZONE_ROOT_DOMAIN
fi

# Default config
if [[ -z "${LOG_LEVEL}" ]]; then
  LOG_LEVEL=1
fi
if [[ -z "${OCM_SINGLE}" ]]; then
  OCM_SINGLE=true
fi
if [[ -z "${MGC_WORKLOAD_CLUSTERS_COUNT}" ]]; then
  MGC_WORKLOAD_CLUSTERS_COUNT=1
fi

cleanup

port80=9090
port443=8445
proxyPort=9200
metalLBSubnetStart=200

# Create network for the clusters
docker network create -d bridge --subnet 172.32.0.0/16 mgc --gateway 172.32.0.1 \
  -o "com.docker.network.bridge.enable_ip_masquerade"="true" \
  -o "com.docker.network.driver.mtu"="1500"

# Create Kind control plane cluster
kindCreateCluster ${KIND_CLUSTER_CONTROL_PLANE} ${port80} ${port443}

# Install the Gateway API CRDs in the control cluster
installGatewayAPI ${KIND_CLUSTER_CONTROL_PLANE}

# Deploy ingress controller
deployIngressController ${KIND_CLUSTER_CONTROL_PLANE}

# Deploy cert manager
deployCertManager ${KIND_CLUSTER_CONTROL_PLANE}

# Initialize local dev setup for the controller on the control-plane cluster
initController ${KIND_CLUSTER_CONTROL_PLANE}

# Deploy OCM hub
deployOCMHub ${KIND_CLUSTER_CONTROL_PLANE}

# Deploy MetalLb
deployMetalLB ${KIND_CLUSTER_CONTROL_PLANE} ${metalLBSubnetStart}

# Add workload clusters if MGC_WORKLOAD_CLUSTERS_COUNT environment variable is set
if [[ -n "${MGC_WORKLOAD_CLUSTERS_COUNT}" ]]; then
  for ((i = 1; i <= ${MGC_WORKLOAD_CLUSTERS_COUNT}; i++)); do
    kindCreateCluster ${KIND_CLUSTER_WORKLOAD}-${i} $((${port80} + ${i})) $((${port443} + ${i})) $((${i} + 1))
    deployIstio ${KIND_CLUSTER_WORKLOAD}-${i}
    installGatewayAPI ${KIND_CLUSTER_WORKLOAD}-${i}
    deployIngressController ${KIND_CLUSTER_WORKLOAD}-${i}
    deployMetalLB ${KIND_CLUSTER_WORKLOAD}-${i} $((${metalLBSubnetStart} + ${i}))
    deployOLM ${KIND_CLUSTER_WORKLOAD}-${i}
    deployOCMSpoke ${KIND_CLUSTER_WORKLOAD}-${i}
  done
fi

# Ensure the current context points to the control plane cluster
kubectl config use-context kind-${KIND_CLUSTER_CONTROL_PLANE}

# TODO: Get values from this file to create configMap
# Create configmap with gateway parameters for clusters
kubectl create configmap gateway-params \
  --from-file=params=config/samples/gatewayclass_params.json \
  -n multi-cluster-gateways