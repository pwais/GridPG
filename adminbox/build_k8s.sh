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

set -o errexit
set -o nounset
set -x

echo "Allowing privileged containers"
mv /opt/kubernetes/cluster/saltbase/pillar/privilege.sls{,.original}
echo "allow_privileged: true" > /opt/kubernetes/cluster/saltbase/pillar/privilege.sls

# TODO: try /var/run/docker.sock mount with boot2docker
docker ps || service docker start

COUNTER=0
LIMIT=10
while ! docker ps -a
do
  echo "$(date) - waiting for docker"
  tail -n10 /var/log/docker.log
  sleep 1
  let COUNTER=COUNTER+1
  if [ $COUNTER -eq $LIMIT ]; then
    echo "Could not start Docker; see /var/log/docker.log"
    exit 1
  fi
done
echo "$(date) - Docker up!"

yes | KUBE_RELEASE_RUN_TESTS=n /opt/kubernetes/build/release.sh

# Clean up
docker rm $(docker ps -a -q)
docker rmi $(docker images -q)

#KUBE_ROOT=/opt/kubernetes
#KUBE_RELEASE_RUN_TESTS=n
#
#source "$KUBE_ROOT/build/common.sh"
#
##kube::build::verify_prereqs
#kube::build::run_build_command hack/build-cross.sh
#kube::build::copy_output
#kube::release::package_tarballs
