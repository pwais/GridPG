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

CMD ["sleep", "infinity"]


