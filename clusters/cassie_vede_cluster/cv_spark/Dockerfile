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

# Java
RUN apt-get install -y openjdk-7-jdk

# Scala / sbt
RUN echo "deb http://dl.bintray.com/sbt/debian /" >> /etc/apt/sources.list.d/sbt.list && \
    apt-get update && \
    apt-get install --force-yes -y sbt && \
	sbt help

# Spark
RUN apt-get -y install curl
WORKDIR /tmp/
RUN curl http://d3kbcqa49mib13.cloudfront.net/spark-1.2.2-bin-hadoop2.4.tgz | tar zxvf -
RUN mv spark-1.2.2-bin-hadoop2.4 /opt/spark
RUN ls -lhat /opt/spark/bin/spark-submit # TODO: better test; --version is broken

# Spark WebUI, worker WebUI, and Task UI
EXPOSE 8080
EXPOSE 8081
EXPOSE 4040

ADD start-master.sh /start-master.sh
RUN chmod a+x /start-master.sh
ADD start-worker.sh /start-worker.sh
RUN chmod a+x /start-worker.sh
ADD test-pi.sh /test-pi.sh
RUN chmod a+x /test-pi.sh
