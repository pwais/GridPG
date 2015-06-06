#!/bin/bash

# Copyright 2015 Maintainers of GridPG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GCLOUD=gcloud
ZONE=${KUBE_GCE_ZONE:-us-central1-b}
MASTER_SIZE=${MASTER_SIZE:-n1-standard-1}
MINION_SIZE=${MINION_SIZE:-n1-standard-1}
NUM_MINIONS=${NUM_MINIONS:-4}
MASTER_DISK_TYPE=pd-standard
MASTER_DISK_SIZE=${MASTER_DISK_SIZE:-20GB}
MINION_DISK_TYPE=pd-standard
MINION_DISK_SIZE=${MINION_DISK_SIZE:-100GB}

OS_DISTRIBUTION=${KUBE_OS_DISTRIBUTION:-debian}
MASTER_IMAGE=${KUBE_GCE_MASTER_IMAGE:-container-vm-v20150505}
MASTER_IMAGE_PROJECT=${KUBE_GCE_MASTER_PROJECT:-google-containers}
MINION_IMAGE=${KUBE_GCE_MINION_IMAGE:-container-vm-v20150505}
MINION_IMAGE_PROJECT=${KUBE_GCE_MINION_PROJECT:-google-containers}
CONTAINER_RUNTIME=docker
RKT_VERSION=${KUBE_RKT_VERSION:-0.5.5}

NETWORK=${KUBE_GCE_NETWORK:-default}
INSTANCE_PREFIX="${KUBE_GCE_INSTANCE_PREFIX:-kubernetes}"
MASTER_NAME="${INSTANCE_PREFIX}-master"
MASTER_TAG="${INSTANCE_PREFIX}-master"
MINION_TAG="${INSTANCE_PREFIX}-minion"
MASTER_IP_RANGE="${MASTER_IP_RANGE:-10.246.0.0/24}"
CLUSTER_IP_RANGE="${CLUSTER_IP_RANGE:-10.244.0.0/16}"
MINION_SCOPES=("storage-ro" "compute-rw" "https://www.googleapis.com/auth/monitoring" "https://www.googleapis.com/auth/logging.write")
PORTAL_NET="10.0.0.0/16"
SERVICE_CLUSTER_IP_RANGE="10.0.0.0/16"  # formerly PORTAL_NET
ALLOCATE_NODE_CIDRS=true

ENABLE_DOCKER_REGISTRY_CACHE=true

# Do not use logging / monitoring
ENABLE_NODE_MONITORING=false
ENABLE_CLUSTER_MONITORING="none"
ENABLE_NODE_LOGGING=false
ENABLE_CLUSTER_LOGGING=false

# Don't require https for our local network, nor the kubernetes master
# TODO can remove the docker-private-registry thing
EXTRA_DOCKER_OPTS="--insecure-registry 10.0.0.0/8 --insecure-registry $MASTER_IP_RANGE --insecure-registry 0.0.0.0/256 "

# For buildbox
ALLOW_PRIVILEGED=true

# Let's DNS
ENABLE_CLUSTER_DNS=true
DNS_SERVER_IP="10.0.0.10"
DNS_DOMAIN="cluster.local"
DNS_REPLICAS=1

ADMISSION_CONTROL=NamespaceLifecycle,NamespaceExists,LimitRanger,SecurityContextDeny,ServiceAccount,ResourceQuota
