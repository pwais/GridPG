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
import time
from optparse import OptionParser
from optparse import OptionGroup

USAGE = (
"""%prog [options]
 
 TODO
 on local machine: --build-and-admin (drop to docker)
 inside local docker: --up (create k8s, start sshfs ...)
 
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
  
  @classmethod
  def run_and_get_json(cls, cmd):
    p = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE)
    r = json.load(p.stdout)
    return r
  
  def run_in_k8s(self, cmd, redacted=False):
    if redacted:
      return self.run_in_shell_redacted("cd " + self.k8s_path + " && " + cmd)
    else:
      return self.run_in_shell("cd " + self.k8s_path + " && " + cmd)
  
  def exec_in_buildbox(self, cmd, redacted=False):
    POD = "gpg-buildbox"
    if not hasattr(self, '_buildbox_host'):
      self._buildbox_host = self.get_pod_host(POD)
    buildbox_host = self._buildbox_host
    EXEC_IN_BUILDBOX = (
      'cluster/kubectl.sh exec -p ' + POD + ' -c ' + POD + ' -- ')
    self.run_in_k8s(EXEC_IN_BUILDBOX + cmd, redacted=redacted)
  
  def gpg_path(self, path):
    return os.path.join(self.gpg_base_path, path)
  
  def cluster_path(self, path):
    return os.path.abspath(os.path.join(self.gpg_cluster_path, path))
  
  def get_pod_host(self, pod_name, wait=True):
    log.info("Finding pod " + pod_name + " ...")
    if wait:
      assert self.wait_for_pod(pod_name)
    
    kubectl = os.path.join(self.k8s_path, "cluster/kubectl.sh")
    r = self.run_and_get_json(kubectl + " get pod " + pod_name + " -o json")
    if r.get("kind") != "Pod":
      log.warn("Did not get pod: %s" % r) 
      return None
    if r.get("metadata", {}).get("name") != pod_name:
      log.warn("Did not get pod with desired name: %s" % r)
      return None
      
    hostIP = r.get("status", {}).get("hostIP")

    if not hostIP:
      log.warn("Pod not found: " + pod_name)
    return hostIP
  
  def get_service_ip(self, service_name):
    log.info("Finding service " + service_name + " ...")
    
    kubectl = os.path.join(self.k8s_path, "cluster/kubectl.sh")
    r = self.run_and_get_json(kubectl + " get service " + service_name + " -o json")
    if r.get("kind") != "Service":
      log.warn("Did not get service: %s" % r) 
      return None
    if r.get("metadata", {}).get("name") != service_name:
      log.warn("Did not get service with desired name: %s" % r)
      return None
      
    portalIP = r.get("spec", {}).get("portalIP")

    if not portalIP:
      log.warn("Service not found: " + service_name)
    return portalIP
  
  def wait_for_pod(self, pod_name, max_wait_sec=300):
    log.info("Waiting for pod " + pod_name + " ...")
      
    kubectl = os.path.join(self.k8s_path, "cluster/kubectl.sh")
    running = False
    waited = 0
    while not running:
      r = self.run_and_get_json(kubectl + " get pod " + pod_name + " -o json")
      log.debug("k8s response: %s" % r)
            
      conds = r.get("status", {}).get("Condition", [])
      running |= any(
        c.get("type") == "Ready" and c.get("status") == "True"
        for c in conds)
      if running:
        break
      
      log.info(
        "... pod " + pod_name + " not running " +
        "(status " + str(conds)  + "), waiting " +
        "(" + str(waited) + " of " + str(max_wait_sec) + ") sec ...")
      WAIT_TIME_SEC = 3
      time.sleep(WAIT_TIME_SEC)
      waited += WAIT_TIME_SEC
      if waited >= max_wait_sec:
        break
      
    if not running:
      log.error("Failed to get pod " + pod_name + "!!! Check status below:")
      self.run_in_k8s("describe pod " + pod_name)
      self.run_in_k8s("log " + pod_name)
      return False
    
    log.info("... pod " + pod_name + " up!")
    return True
  
#   def get_docker_private_registry(self):
#     if not hasattr(self, '_docker_reg_host'):
#       log.info("Finding docker-private-registry ...")
#       self._docker_reg_host = self.get_service_ip("docker-private-registry")
#     return self._docker_reg_host
  
  def push_to_remote_docker_registry(self, tag, reg_host=None):
    if not reg_host:
      reg_host = "docker-private-registry"
    
    self.run_in_shell("docker tag " + tag + " " + reg_host + ":5000/" + tag)
    self.run_in_shell("docker push " + reg_host + ":5000/" + tag)
  
  def buildbox_push_to_private_reg(self, tag):
    reg_host = self.get_docker_private_registry()
    self.exec_in_buildbox("docker tag " + tag + " " + reg_host + ":5000/" + tag)
    self.exec_in_buildbox("docker push " + reg_host + ":5000/" + tag)
  
  def buildbox_docker_build(self, remote_path, tag):
    self.exec_in_buildbox(
      'sh -c "cd ' + remote_path + ' && docker build -t ' + tag + ' ."')
  
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
    k8s_defs = tuple()
    if hasattr(self.c, "k8s_create_defs"):
      k8s_defs = k8s_defs + self.c.k8s_create_defs(self)
    for path in k8s_defs:
      self.run_in_k8s("./cluster/kubectl.sh create -f " + path)
    log.info("... done.")

    # Post-create setup
    if hasattr(self.c, "after_up"):
      log.info("Running post-cluster setup ...")
      self.c.after_up(self)
      log.info("... done.")

    log.info("Cluster up!!")

  def down(self):
    self.run_in_k8s("./cluster/kube-down.sh")
  
  def buildbox_sshfs_remote_mount(self, local_path, remote_path=None):
    if not remote_path:
      remote_path = local_path
    
    log.info("Mounting " + local_path + " to remote buildbox via sshfs ...")
    ssh_key_path = "/root/.ssh/id_dsa_gpg_sshfs"
    ssh_key_pub_path = "/root/.ssh/id_dsa_gpg_sshfs.pub"
    if not os.path.exists(ssh_key_path):
      log.info("... generating new ssk key for buildbox ...")
      self.run_in_shell("ssh-keygen -t dsa -P '' -f " + ssh_key_path)
      log.info("... authorizing locally ...")
      self.run_in_shell("/opt/accept_gpg_sshfs_key.sh")
    
    log.info("... installing ssh keys on buildbox (cmd will be redacted) ... ")
    self.exec_in_buildbox('mkdir -p /root/.ssh')
    for path in (ssh_key_path, ssh_key_pub_path):
      content = open(path, 'r').read()
      # NB: we use sh -c to make the > redirect explicitly run *remotely*
      # NB: also, we use echo here because, sadly, cat | kubcetl -- tee
      # doesn't work-- it blocks indefinitely (looks like a Golang / k8s bug) 
      self.exec_in_buildbox(
        'sh -c "echo \'' + content +  '\' > ' + path + ' "', redacted=True)
    
    log.info("... authorizing copied key and bouncing sshd ...")
    self.exec_in_buildbox('/opt/accept_gpg_sshfs_key.sh')
    
    # NB: We use a custom port so as to not interfere with host / k8s ssh
    SSH_PORT = "30022"
    
    # TODO: can we make this provider agnostic eventually?
    log.info("... adding firewall rule to open ssh ...")
    if self.provider == "gce":
      RULE_NAME = "gpg-buildbox-ssh"
      rule_exists = False
      resp = self.run_and_get_json(
        "gcloud compute firewall-rules list --format json")
      for rule in resp:
        if rule.get("name") == RULE_NAME:
          rule_exists = True
          break
      if not rule_exists:
        self.run_in_shell(
          "gcloud compute firewall-rules create " + RULE_NAME +
          " --allow=tcp:" + SSH_PORT)
    elif self.provider == "aws":
      assert False, "TODO TODO TODO"
    else:
      log.warn(
        "Don't know how to add firewall rule for provider %s" % self.provider)  
    
    log.info("... testing ssh ...")
    BUILDBOX_HOST = self.get_pod_host("gpg-buildbox")
    SSH_CMD_BASE = (
      "ssh " + BUILDBOX_HOST + " -p " + SSH_PORT + " -i  " + ssh_key_path + " ")
    self.run_in_shell(SSH_CMD_BASE + "uptime")
      
    log.info("... starting tunneled sshfs ...")
    # We must create an empty directory for the mounted file system
    # or sshfs will crash.  We'll 
    self.exec_in_buildbox("mkdir -p " + remote_path)
    self.run_in_shell(
      SSH_CMD_BASE +
      # Forward local SSH_PORT remotely as port 9900
      "-nT -R 9900:localhost:" + SSH_PORT +
      # Have remote host sshfs back to our local machine through the
      # forwarded 30020 port.  Use our special purpose ssh key.
      " -- sshfs -p 9900 -o IdentityFile=/root/.ssh/id_dsa_gpg_sshfs " +
      # Tell sshfs to mount `local_path` (read from the forwarded 30020 port)
      # to `remote_path` on the remote host
      "localhost:" + local_path + " " + remote_path +" &")
    
    log.info("... testing remote mount ...")
    self.exec_in_buildbox("ls -lhat " + remote_path)
    
    log.info("... local path mounted remotely! Done!!")
    
    # gcloud compute firewall-rules create --allow=tcp:10022 --target-tags=kubernetes-minion kubernetes-minion-10022
    
    # adminbox must listen on 10022 /etc/ssh/sshd_config
    # root@boot2docker:/opt/GridPG# ssh -nT -R 9000:localhost:30022 104.154.85.153 -p 10022 -i ~/.ssh/id_dsa_gpg_sshfs -- sshfs -p 9000 -o IdentityFile=/root/.ssh/id_dsa_gpg_hfs localhost:/opt/GridPG /opt/GridPGMounted &
    
#     self.run_in_shell(
#       EXEC_IN_BUILDBOX +
#       'sh -c "cat /root/.ssh/id_dsa_gpg_sshfs.pub > /root/.ssh/authorized_keys"')
#     
#     self.run_in_shell(
#       EXEC_IN_BUILDBOX +
#       'sh -c "echo \"AuthorizedKeysFile .ssh/authorized_keys\" ' +
#         '> /etc/sshd/sshd_config')
    
    

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
    "--buildbox-tag", default="gpg-buildbox",
    help="Give the buildbox image this tag [default %default]")
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
    "--build-and-admin", default=False, action="store_true",
    help="Build user host deps and drop into a user adminbox")
  option_parser.add_option_group(local_group)
  
  adminbox_group = OptionGroup(
                    option_parser,
                    "Adminbox",
                    "Adminbox Actions")
  adminbox_group.add_option(
    "--adminbox-build", default=False, action="store_true",
    help="Build the gpg-adminbox image")
  adminbox_group.add_option(
    "--adminbox-start", default=False, action="store_true",
    help="Start a gpg-adminbox container")
  adminbox_group.add_option(
    "--adminbox-rm", default=False, action="store_true",
    help="Remove the gpg-adminbox container")
  adminbox_group.add_option(
    "--in-adminbox", default=False, action="store_true",
    help="Drop into a Dockerized adminbox shell")
  option_parser.add_option_group(adminbox_group)
  
  buildbox_group = OptionGroup(
                    option_parser,
                    "Buildbox",
                    "Buildbox Actions")
  buildbox_group.add_option(
    "--buildbox-build", default=False, action="store_true",
    help="Build the gpg-buildbox image")
  buildbox_group.add_option(
    "--buildbox-build-and-push", default=False, action="store_true",
    help="Build the gpg-buildbox and push (public release)")
  option_parser.add_option_group(buildbox_group)
  
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
  
  
  # Meta-opts
  if opts.build_and_admin:
    opts.buildbox_build = True
    opts.adminbox_build = True
    opts.in_adminbox = True
  
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
  
  if opts.buildbox_build or opts.buildbox_build_and_push:
    run_in_shell("cd buildbox && docker build -t " + opts.buildbox_tag + " .")

  if opts.buildbox_build_and_push:
    # TODO: gpg docker account
    run_in_shell(
      "docker tag -f " + opts.buildbox_tag + " pwais/hack && "
      "docker push pwais/hack")
  
  if opts.adminbox_build:
    run_in_shell("cd adminbox && docker build -t " + opts.adminbox_tag + " .")

  if opts.adminbox_start or opts.in_adminbox:
    run_in_shell(
      "docker run -d --net=host --name=gpg-adminbox -p 30022:30022 " +
      "--privileged " +
      "-v " + os.path.abspath(".") + ":/opt/GridPG " +
      "-w /opt/GridPG " + opts.adminbox_tag)
    log.info("Building k8s ...")
    run_in_shell("docker exec gpg-adminbox /opt/build_k8s.sh")
    log.info("... done building k8s")
  
  if opts.in_adminbox:  
    docker_cmd = "docker exec -it gpg-adminbox bash"
    log.info("Dropping into shell: " + docker_cmd)
    os.execvp("docker", docker_cmd.split(" "))

  if opts.adminbox_rm:
    run_in_shell("docker kill gpg-adminbox && docker rm gpg-adminbox")

  if opts.up or opts.down:
    c = ClusterContext.load_from(opts.cluster)
    c.provider = opts.provider
    c.k8s_path = opts.k8s_path
    
    if opts.up:
      c.up()
    elif opts.down:
      c.down()
