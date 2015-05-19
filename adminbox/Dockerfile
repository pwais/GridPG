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

# Core
RUN apt-get install -y python2.7 python-pip curl wget git

# Utils
RUN apt-get install -y iftop screen time sshfs sudo lsof s3cmd vim

# Go
WORKDIR /tmp
RUN wget https://storage.googleapis.com/golang/go1.4.2.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.4.2.linux-amd64.tar.gz
RUN rm go1.4.2.linux-amd64.tar.gz
RUN echo "PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
ENV PATH $PATH:/usr/local/go/bin
RUN go version

# K8s
RUN git clone --branch release-0.17 --depth 1  https://github.com/GoogleCloudPlatform/kubernetes.git /opt/kubernetes
WORKDIR /opt/kubernetes
RUN ./hack/build-go.sh

