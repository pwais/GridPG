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

FROM ubuntu:trusty

RUN apt-get update

# Build Core
RUN apt-get install -y python2.7 python-pip curl wget git

# Utils
RUN apt-get install -y iftop screen time sshfs sudo lsof s3cmd vim man links 

# Docker
# TODO: upgrade to current docker when k8s upgrades their images
#RUN wget -qO- https://get.docker.com/ | sh
RUN wget -qO- https://get.docker.com/ | sed -r 's/apt-get install -y -q lxc-docker/apt-get install -y -q lxc-docker-1.6.0/g' | sh

# SSH
RUN apt-get -y install openssh-server

ADD accept_gpg_sshfs_key.sh /opt/accept_gpg_sshfs_key.sh
RUN chmod a+x /opt/accept_gpg_sshfs_key.sh

# We'll use this port for sshfs
EXPOSE 30022 

ADD startup.sh /opt/startup.sh
RUN chmod a+x /opt/startup.sh
CMD /opt/startup.sh
