# Copyright 2015 Maintainers of CassieVede
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

# Java
RUN apt-get install -y openjdk-7-jdk

# Cassie.  FMI see https://wiki.apache.org/cassandra/DebianPackaging
RUN echo "deb http://www.apache.org/dist/cassandra/debian 21x main" >> /etc/apt/sources.list.d/cassandra.list && \
    echo "deb-src http://www.apache.org/dist/cassandra/debian 21x main" >> /etc/apt/sources.list.d/cassandra.list && \
    gpg --keyserver pgp.mit.edu --recv-keys F758CE318D77295D && \
	gpg --export --armor F758CE318D77295D | sudo apt-key add -  && \
	gpg --keyserver pgp.mit.edu --recv-keys 2B5C1B00 && \
	gpg --export --armor 2B5C1B00 | sudo apt-key add - && \
	gpg --keyserver pgp.mit.edu --recv-keys 0353B12C && \
	gpg --export --armor 0353B12C | sudo apt-key add - && \
	apt-get update && \
	apt-get -qq -y install cassandra

ADD cassandra.yaml /etc/cassandra/cassandra.yaml

ADD https://github.com/GoogleCloudPlatform/kubernetes/blob/b4b4ac4ad3e3040fb9ab1c2fd1e30cb3efd0f4bd/examples/cassandra/image/kubernetes-cassandra.jar?raw=true /opt/kubernetes-cassandra.jar 

# Cassandra CQL and Thrift
EXPOSE 9042
EXPOSE 9160 

ADD startup.sh /startup.sh
RUN chmod a+x /startup.sh
CMD /startup.sh
