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

FROM gpg-buildbox

# AWS
RUN apt-get install -y groff unzip
WORKDIR /tmp
RUN curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
RUN unzip awscli-bundle.zip
RUN sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
RUN rm -rf ./awscli-bundle
RUN echo "Test" && aws --version

# GCE
WORKDIR /opt/google-cloud-sdk
RUN curl https://dl.google.com/dl/cloudsdk/release/google-cloud-sdk.tar.gz | tar xzvf -
RUN ./google-cloud-sdk/install.sh
RUN echo "# The next line updates PATH for the Google Cloud SDK." >> /etc/profile && \
    echo "source '/opt/google-cloud-sdk/google-cloud-sdk/path.bash.inc'" >> /etc/profile && \
    echo "# The next line enables bash completion for gcloud." >> /etc/profile && \
    echo "source '/opt/google-cloud-sdk/completion.bash.inc'" >> /etc/profile
ENV PATH $PATH:/opt/google-cloud-sdk/google-cloud-sdk/bin
RUN echo "Test" && gcloud --version
RUN gcloud config set --scope=user disable_usage_reporting true

# Go
WORKDIR /tmp
RUN wget https://storage.googleapis.com/golang/go1.4.2.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.4.2.linux-amd64.tar.gz
RUN rm go1.4.2.linux-amd64.tar.gz
RUN echo "PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
ENV PATH $PATH:/usr/local/go/bin
RUN echo "Test" && go version

# K8s
#WORKDIR /opt/

# To use a release:
#RUN curl https://storage.googleapis.com/kubernetes-release/release/v0.17.0/kubernetes.tar.gz | tar xzvf -

# To use source:
#RUN git clone --branch release-0.17 --depth 1  https://github.com/GoogleCloudPlatform/kubernetes.git /opt/kubernetes
# NB: build requires docker; must be run outside of $ docker build

#ADD .kubernetes /opt/kubernetes
#WORKDIR /opt/kubernetes
#RUN KUBE_RELEASE_RUN_TESTS=n build/release.sh
#RUN ./hack/build-go.sh
#ADD build_k8s.sh build/custom_build_k8s.sh
#RUN bash build/custom_build_k8s.sh

# Make k8s / GCE run smoother (but not required)
RUN gcloud components update preview
RUN gcloud components update alpha
RUN gcloud components update

ADD build_k8s.sh /opt/build_k8s.sh
CMD chmod a+x /opt/build_k8s.sh

CMD /opt/startup.sh

