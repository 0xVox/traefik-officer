#!/usr/bin/env bash

## Used to deploy the example locally. Download KIND to run this.
set -e

kind_cluster_name='traefik-officer'
reg_name='kind_registry'
reg_port='5000'
running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"

if [ "${running}" != 'true' ]; then
  docker run -d --restart=always -p "${reg_port}:5000" --name "${reg_name}" registry:2
fi
reg_ip="$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "${reg_name}")"

cat << EOF > kind_local_cluster_config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.16.4@sha256:b91a2c2317a000f3a783489dfb755064177dbc3a0b2f4147d50f04825d016f55

- role: worker
  image: kindest/node:v1.16.4@sha256:b91a2c2317a000f3a783489dfb755064177dbc3a0b2f4147d50f04825d016f55
- role: worker
  image: kindest/node:v1.16.4@sha256:b91a2c2317a000f3a783489dfb755064177dbc3a0b2f4147d50f04825d016f55
- role: worker
  image: kindest/node:v1.16.4@sha256:b91a2c2317a000f3a783489dfb755064177dbc3a0b2f4147d50f04825d016f55
containerdConfigPatches: 
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_ip}:${reg_port}"]
EOF

kind create cluster --name $kind_cluster_name --config ./kind_local_cluster_config.yaml

echo "KIND CLuster created: "
kubectl get nodes

echo "Run: `kubectl apply -f ./traefik_with_officer.yaml` to deploy the example locally in KIND."
