# Use golang as a base image because go is currently tricky to install
FROM golang:1.4

RUN apt-get update
RUN apt-get install -y curl wget rsync less sudo vim 

# Get etcd.
RUN wget https://github.com/coreos/etcd/releases/download/v2.0.5/etcd-v2.0.5-linux-amd64.tar.gz -O etcd-linux-amd64.tar.gz && \
  tar -C /usr/local/ -xzf etcd-linux-amd64.tar.gz && \
  mv /usr/local/etcd-v2.0.5-linux-amd64 /usr/local/etcd && \
  ln -s /usr/local/etcd/etcd /usr/bin/etcd && \
  ln -s /usr/local/etcd/etcd-migrate /usr/bin/etcd-migrate && \
  ln -s /usr/local/etcd/etcdctl /usr/bin/etcdctl && \
  rm etcd-linux-amd64.tar.gz

# Get docker and test
RUN wget -qO- https://get.docker.com/ | sh

ADD startup.sh /
CMD /startup.sh && tail -F /tmp/kube*
