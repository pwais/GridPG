#!/usr/bin/python

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

import imp
import json
import logging
import os
import sys
import subprocess
from optparse import OptionParser
from optparse import OptionGroup

USAGE = (
"""%prog [options]
 
 
 
 * Requires local docker
 * Requires network access for --deps
 * Tested in Python 2.7
""")

LOG_FORMAT = "%(asctime)s\t%(name)-4s %(process)d : %(message)s"

# Direct all script output to a log
log = logging.getLogger("ctl")
log.setLevel(logging.INFO)
console_handler = logging.StreamHandler(stream=sys.stderr)
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
log.addHandler(console_handler)

def run_in_shell(cmd):
    log.info("Running %s ..." % cmd)
    subprocess.check_call(cmd, shell=True)
    log.info("... done")



class EmptyCluterDef(object):
  
  @staticmethod
  def before_up(ctx):
    return None
  
  @staticmethod
  def k8s_up_env(ctx):
    return {}
  
  @staticmethod
  def before_create_defs(ctx):
    return None
  
  @staticmethod
  def k8s_create_defs(ctx):
    return tuple()
  
  @staticmethod
  def after_up(ctx):
    return None

class ClusterContext(object):
  
  gpg_base_path = os.path.abspath(".")
  
  def __init__(self, c_cls, gpg_cluster_path=None):  
    self.gpg_cluster_path = gpg_cluster_path
    self.c = c_cls()
    self.provider = "gce"
    self.k8s_path = "/opt/kubernetes"
    self.log = log
  
  ### Utils
  
  @classmethod
  def run_in_shell(cls, cmd):
    return run_in_shell(cmd)
  
  @classmethod
  def run_in_shell_redacted(cls, cmd):
    log.info("Running a redacted command... ")
    subprocess.check_call(cmd, shell=True)
    log.info("... done.")
  
  def run_in_k8s(self, cmd):
    return run_in_shell("cd " + self.k8s_path + " && " + cmd)
  
  def gpg_path(self, path):
    return os.path.join(self.gpg_base_path, path)
  
  def cluster_path(self, path):
    return os.path.abspath(os.path.join(self.gpg_cluster_path, path))
  
  def get_pod_host(self, pod_name):
    log.info("Finding pod " + pod_name + " ...")
      
    kubectl = os.path.join(self.k8s_path, "cluster/kubectl.sh")
    p = subprocess.Popen(
          (kubectl + " get pod " + pod_name + " -o json").split(" "),
          stdout=subprocess.PIPE)
    r = json.load(p.stdout)
    if r.get("kind") != "Pod":
      return None
    if r.get("metadata", {}).get("name") != pod_name:
      return None
      
    hostIP = r.get("status", {}).get("hostIP")

    if not hostIP:
      log.warn("Pod not found: " + pod_name)
    return hostIP
  
  def push_to_remote_docker_registry(self, tag):
    if not hasattr(self, '_docker_private_registry_host'):
      log.info("Finding docker-private-registry ...")
      
      kubectl = os.path.join(self.k8s_path, "cluster/kubectl.sh")
      p = subprocess.Popen(
            (kubectl + " get pods -o json").split(" "),
            stdout=subprocess.PIPE)
      resp = json.load(p.stdout)
      for r in resp.get("items", []):
        if r.get("kind") != "Pod":
          continue
        if r.get("metadata", {}).get("name") != "docker-private-registry":
          continue
        
        self._docker_private_registry_host = r.get("status", {}).get("hostIP")
        break
    
    reg_host = self._docker_private_registry_host
    self.run_in_shell("docker tag " + tag + " " + reg_host + ":5000/" + tag)
    self.run_in_shell("docker push " + reg_host + ":5000/" + tag)
  
  ### Actions
  
  @staticmethod
  def load_from(dir_path):
    assert os.path.exists(dir_path), "No cluster directory: %s" % dir_path
    f, fname, desc = imp.find_module("gpg_cluster_def", [dir_path])
    try:
      gpg_cluster_def = imp.load_module("gpg_cluster_def", f, fname, desc)
      log.info("Loaded cluster from %s" % dir_path)
    finally:
      f.close()
    
    return ClusterContext(gpg_cluster_def.Cluster, gpg_cluster_path=dir_path)
    
  def up(self):
    
    # Prepare
    if hasattr(self.c, "before_up"):
      log.info("Running cluster setup ...")
      self.c.before_up(self)
      log.info("... done.")
    
    # Start the cluster
    env = {"KUBERNETES_PROVIDER": self.provider}
    if hasattr(self.c, "k8s_up_env"):
      env.update(self.c.k8s_up_env(self))
    cmd = " ".join(k + "=" + v for (k, v) in env.iteritems())
    cmd += " ./cluster/kube-up.sh"
    log.info("Starting cluster ...")
    self.run_in_k8s(cmd)
    log.info("... done.")
    
    # Prepare to create pods
    if hasattr(self.c, "before_create_defs"):
      log.info("Running post-up setup ...")
      env.update(self.c.before_create_defs(self))
      log.info("... done.")
    
    # Create k8s entities
    log.info("Creating k8s entities ...")
    k8s_defs = (
      self.gpg_path("k8s_specs/docker-private-registry.yaml"),
      self.gpg_path("k8s_specs/docker-private-registry-service.yaml"))
    if hasattr(self.c, "k8s_create_defs"):
      k8s_defs = k8s_defs + self.c.k8s_create_defs(self)
    for path in k8s_defs:
      self.run_in_k8s("./cluster/kubectl.sh create -f " + path)
    log.info("... done.")

    # Post-create setup
    if hasattr(self.c, "after_up"):
      log.info("Running post-cluster setup ...")
      env.update(self.c.after_up(self))
      log.info("... done.")

    self.run_in_k8s("./cluster/kubectl.sh get pods")

  def down(self):
    self.run_in_k8s("./cluster/kube-down.sh")
  
  def tunnel(self):
    ssh_key_path = os.path.abspath(os.path.expanduser("~/.ssh/id_dsa_gpg_sshfs"))
    ssh_key_pub_path = os.path.abspath(os.path.expanduser("~/.ssh/id_dsa_gpg_sshfs.pub"))
    if not os.path.exists(ssh_key):
      self.run_in_shell("ssh-keygen -t dsa -P '' -f " + ssh_key_path)
    
    adminbox_host = self.get_pod_host("gpg-adminbox")
    
    EXEC_IN_ADMINBOX = (
      'cluster/kubectl.sh exec -p gpg-adminbox -c gpg-adminbox -- ')
    
    log.info("Installing ssh keys on cluster adminbox... ")
    self.run_in_shell(
        EXEC_IN_ADMINBOX + 'mkdir -p /root/.ssh')
    for path in (ssh_key_path, ssh_key_pub_path):
      content = open(path, 'r').read()
      # NB: we use sh -c to make the > redirect explicitly run *remotely*
      self.run_in_shell_redacted(
        EXEC_IN_ADMINBOX + 'sh -c "echo \"' + content +  '\" > ' + path + ' "')
    
    log.info("... authorizing copied key ...")
    self.run_in_shell(EXEC_IN_ADMINBOX + '/opt/accept_gpg_sshfs_key.sh')
    
    
    
    # gcloud compute firewall-rules create --allow=tcp:10022 --target-tags=kubernetes-minion kubernetes-minion-10022
    
    # adminbox must listen on 10022 /etc/ssh/sshd_config
    # root@boot2docker:/opt/GridPG# ssh -nT -R 9000:localhost:30022 104.154.85.153 -p 10022 -i ~/.ssh/id_dsa_gpg_sshfs -- sshfs -p 9000 -o IdentityFile=/root/.ssh/id_dsa_gpg_hfs localhost:/opt/GridPG /opt/GridPGMounted &
    
#     self.run_in_shell(
#       EXEC_IN_ADMINBOX +
#       'sh -c "cat /root/.ssh/id_dsa_gpg_sshfs.pub > /root/.ssh/authorized_keys"')
#     
#     self.run_in_shell(
#       EXEC_IN_ADMINBOX +
#       'sh -c "echo \"AuthorizedKeysFile .ssh/authorized_keys\" ' +
#         '> /etc/sshd/sshd_config')
    
    log.info("... done .")

if __name__ == "__main__": 
  
  # Flags! No, wait, they"re *options* ...
  option_parser = OptionParser(usage=USAGE)
  
  config_group = OptionGroup(
                    option_parser,
                    "Config",
                    "Configuration")
  config_group.add_option(
    "--provider", default="gce",
    help="Use this k8s cloud provider [default %default]")
  config_group.add_option(
    "--k8s-path", default="/opt/kubernetes",
    help="Use this Kubernetes [default %default]")
  config_group.add_option(
    "--cluster", default=os.path.abspath("clusters/base_dev_cluster"),
    help="Path to cluster files [default %default]")
  config_group.add_option(
    "--adminbox-tag", default="gpg-adminbox",
    help="Give the adminbox image this tag [default %default]")
  config_group.add_option(
    "--registry", default="kubernetes-master",
    help="Use the registry on this host [default %default]")
  option_parser.add_option_group(config_group)
  
  local_group = OptionGroup(
                    option_parser,
                    "Local",
                    "Local Actions")
  local_group.add_option(
    "--deps", default=False, action="store_true",
    help="Set up local dependencies")
  local_group.add_option(
    "--clean", default=False, action="store_true",
    help="Clean local dependencies")
  local_group.add_option(
    "--adminbox-build", default=False, action="store_true",
    help="Build the gpg-adminbox image")
  local_group.add_option(
    "--adminbox-build-and-push", default=False, action="store_true",
    help="Build the gpg-adminbox and push (public release)")
  local_group.add_option(
    "--in-adminbox", default=False, action="store_true",
    help="Drop into a Dockerized adminbox shell")
  option_parser.add_option_group(local_group)
  
  cluster_group = OptionGroup(
                    option_parser,
                    "Cluster",
                    "Cluster Actions")
  cluster_group.add_option(
    "--up", default=False, action="store_true",
    help="Bring the cluster up")
  cluster_group.add_option(
    "--down", default=False, action="store_true",
    help="Destroy the cluster")
  option_parser.add_option_group(cluster_group)
  
  # -- Try adding --privileged to k8s conig (or CAP for mounting so DID works?)
  #     and see if we can run adminbox in k8s.  see if we can DID build
  #     containers and push to k8s repo (will require insecure-reg inside docker)
  #       Then we can have a build box, and write things to run inside it;
  #       expose the  destination reg thru ENV or use the K8S env.  Even
  #       run Travis??!  
  # -- add reg repo to use.  gridpg will commit tags to that repo
  # -- add --insecure-reg to the master machine's docker.  
  # -- 
#   reg_group = OptionGroup(
#                     option_parser,
#                     "Registry",
#                     "Local Docker Registry Actions")
#   reg_group.add_option(
#     "--reg-up", default=False, action="store_true",
#     help="Bring up the local (private) Docker registry")
#   reg_group.add_option(
#     "--reg-down", default=False, action="store_true",
#     help="Bring down the local (private) Docker registry")
#   option_parser.add_option_group(reg_group)
  
  opts, args = option_parser.parse_args()
  
  
  
  assert os.path.exists("LICENSE"), "Please run from root of a GridPG distro"
  
  
  
  if opts.deps:
    # Pull git friends
    run_in_shell("git submodule update --init")

#     # Build k8s
#     run_in_shell("cd deps/kubernetes && make quick-release")
#     
#     log.info("Placing kubernetes for adminbox build ...")
#     run_in_shell("cp -r deps/kubernetes adminbox/.kubernetes")
#     log.info("... done.")
#     log.info(
#       "Nota bene: the k8s build process may leave behind some large "
#       "(and dangling) docker images.  Run "
#       "  docker rmi $(docker images -f \"dangling=true\" -q) "
#       "to free up some disk space.")

  if opts.clean:
    run_in_shell("rm -rf deps/*")
  
  if opts.adminbox_build or opts.adminbox_build_and_push:
    run_in_shell("cd adminbox && docker build -t " + opts.adminbox_tag + " .")
    
    
    # TODO: fix major docker commit space issue 
#     log.info("Pre-building k8s in adminbox (this is slow) ...")
#     
#     log.info(
#       "NB: Requires docker in docker.  If container startup fails "
#       "(check $ docker logs gpg-adminbox-build-temp) try restarting docker.") 
#     run_in_shell(
#       "docker run -d --name=gpg-adminbox-build-temp --privileged gpg-adminbox")
#     run_in_shell("docker exec gpg-adminbox-build-temp /opt/build_k8s.sh")
#     run_in_shell("docker commit gpg-adminbox-build-temp gpg-adminbox")
#     run_in_shell(
#       "docker kill gpg-adminbox-build-temp && docker rm gpg-adminbox-build-temp")
#     
#     log.info("... done.")

  if opts.adminbox_build_and_push:
    # TODO: gpg docker account
    run_in_shell(
      "docker tag -f " + opts.adminbox_tag + " pwais/hack && "
      "docker push pwais/hack")

  if opts.in_adminbox:
    run_in_shell(
      "docker run -d --net=host --name=gpg-adminbox -P " +
      "--privileged " +
#       "--cap-add SYS_ADMIN --device /dev/fuse " + # For SSHFS
      "-v " + os.path.abspath(".") + ":/opt/GridPG " +
      "-w /opt/GridPG " +
      opts.adminbox_tag + " bash")
    docker_cmd = "docker exec -it gpg-adminbox bash"
    log.info("Dropping into shell: " + docker_cmd)
    os.execvp("docker", docker_cmd.split(" "))

  if opts.up or opts.down:
    c = ClusterContext.load_from(opts.cluster)
    c.provider = opts.provider
    c.k8s_path = opts.k8s_path
    
    if opts.up:
      c.up()
    elif opts.down:
      c.down()
