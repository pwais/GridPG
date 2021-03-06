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
 
 TODO: also mount k8s in docker so we save build. or make build deps..
 
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

DEFAULT_BASE_CLUSTER_PATH = os.path.abspath("clusters/base_dev_cluster")

class EmptyCluterDef(object):
  
  def before_up(self, ctx):
    return None
  
  def k8s_up_env(self, ctx):
    return {}
  
  def k8s_create_defs(self, ctx):
    return tuple()
  
  def after_up(self, ctx):
    return None

  def test_cluster(self, ctx):
    return None

class ComposedClusterDef(object):
  
  def __init__(self, cs):
    self.cs = cs
    
  def before_up(self, ctx):
    for c in self.cs:
      c.before_up(ctx)
  
  def k8s_up_env(self, ctx):
    evars = {}
    for c in self.cs:
      evars.update(c.k8s_up_env(ctx))
    return evars
  
  def k8s_create_defs(self, ctx):
    defs = []
    for c in self.cs:
      defs += c.k8s_create_defs(ctx)
    return defs
  
  def after_up(self, ctx):
    for c in self.cs:
      c.after_up(ctx)

  def test_cluster(self, ctx):
    for c in self.cs:
      c.test_cluster(ctx)


class ClusterContext(object):
  
  gpg_base_path = os.path.abspath(".")
  
  def __init__(self, c, opts):
    self.c = c
    self.opts = opts
    self.log = log
  
  
  ###
  ### Utils
  ###
  
  def run_in_shell(self, cmd):
    return run_in_shell(cmd)
  
  def run_in_shell_redacted(self, cmd):
    log.info("Running a redacted command... ")
    subprocess.check_call(cmd, shell=True)
    log.info("... done.")
  
  def run_and_get_txt(self, cmd):
    log.info("Running %s and reading stdout..." % cmd)
    p = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE)
    out = p.stdout.read()
    log.info("... done.")
    return out
  
  def run_with_stdin(self, cmd, stdin_data):
    log.info("Running %s and sending stdin..." % cmd)
    p = subprocess.Popen(cmd.split(" "), stdin=subprocess.PIPE)
    p.stdin.write(stdin_data)
    p.stdin.flush()
    p.stdin.close()
    p.wait()
    log.info("... done.")
  
  def run_and_get_json(self, cmd):
    return json.loads(self.run_and_get_txt(cmd))
  
  def run_in_k8s(self, cmd, redacted=False):
    if redacted:
      return self.run_in_shell_redacted("cd " + self.opts.k8s_path + " && " + cmd)
    else:
      return self.run_in_shell("cd " + self.opts.k8s_path + " && " + cmd)
  
  def run_k8s_templated_create_def(self, path):
    spec = open(path, 'r').read()
    DPR_TOKEN = "%%docker-private-registry%%"
    if DPR_TOKEN in spec:
      private_registry = self.get_docker_private_registry()
      spec = spec.replace(DPR_TOKEN, private_registry + ":5000")
    kubectl = os.path.join(self.opts.k8s_path, "cluster/kubectl.sh")
    cmd = kubectl + " create -f -"
    self.run_with_stdin(cmd, spec)
  
  def exec_in_buildbox(self, cmd, pod="gpg-buildbox", redacted=False):
    buildbox_host = self.get_pod_host(pod)
    EXEC_IN_BUILDBOX = (
      'cluster/kubectl.sh exec ' + pod + ' -c ' + pod + ' -- ')
    self.run_in_k8s(EXEC_IN_BUILDBOX + cmd, redacted=redacted)
  
  def gpg_path(self, path):
    return os.path.join(self.gpg_base_path, path)
  
  def cluster_path(self, path):
    return os.path.abspath(os.path.join(self.opts.cluster, path))
  
  def get_pod(self, pod_name, wait=True, use_cache=True):
    if not hasattr(self, '_get_pod_cache'):
      self._get_pod_cache = {}
    
    if use_cache and pod_name in self._get_pod_cache:
      return self._get_pod_cache[pod_name]
    
    log.info("Finding pod " + pod_name + " ...")
    if wait:
      assert self.wait_for_pod(pod_name)
    
    kubectl = os.path.join(self.opts.k8s_path, "cluster/kubectl.sh")
    r = self.run_and_get_json(kubectl + " get pod " + pod_name + " -o json")
    if r.get("kind") != "Pod":
      log.warn("Did not get pod: %s" % r) 
      return None
    if r.get("metadata", {}).get("name") != pod_name:
      log.warn("Did not get pod with desired name: %s" % r)
      return None
    
    self._get_pod_cache[pod_name] = r
    return r

  def get_nodes(self, use_cache=True):
    if use_cache and hasattr(self, '_get_nodes_cache'):
      return self._get_nodes_cache
    
    kubectl = os.path.join(self.opts.k8s_path, "cluster/kubectl.sh")
    r = self.run_and_get_json(kubectl + " get nodes -o json")
    nodes = r.get("items", [])
    log.info("Got info on %s nodes", len(nodes))
    self._get_nodes_cache = nodes
    return self._get_nodes_cache
    

  def get_pod_host(self, pod_name, wait=True):
    pod = self.get_pod(pod_name, wait=wait)
    
    # k8s v1.0 now returns internal, virtual IPs for hostIP :P
    # So we have to find the node associated with the pod host
    # in a backwards manner
    
    hostInternalIP = pod.get("status", {}).get("hostIP")
    log.info("Looking for node who owns internal ip " + hostInternalIP)
    nodes = self.get_nodes()
    hostIP = None
    for n in nodes:
      if n.get("kind") == "Node":
        addrs = n.get("status", {}).get("addresses", [])
        intIP = None
        extIP = None
        for addr in addrs:
          if addr.get("type") == "InternalIP":
            intIP = addr.get("address")
          elif addr.get("type") == "ExternalIP":
            extIP = addr.get("address")
        if intIP == hostInternalIP:
          hostIP = extIP
          log.info("Pod is on host %s" % n.get("metadata", {}).get("name", ""))
          break

    if not hostIP:
      log.warn("Can't get hostIP for pod: %s" % pod)
    return hostIP
  
  def get_pod_ip(self, pod_name, wait=True):
    pod = self.get_pod(pod_name, wait=wait)
    podIP = pod.get("status", {}).get("podIP")

    if not podIP:
      log.warn("Can't get podIP from pod: " + pod)
    return podIP
  
  def get_service_ip(self, service_name, use_cache=True):
    if not hasattr(self, '_get_service_ip_cache'):
      self._get_service_ip_cache = {}
    
    if use_cache and service_name in self._get_service_ip_cache:
      return self._get_service_ip_cache[service_name]
    
    log.info("Finding service " + service_name + " ...")
    
    kubectl = os.path.join(self.opts.k8s_path, "cluster/kubectl.sh")
    r = self.run_and_get_json(kubectl + " get service " + service_name + " -o json")
    if r.get("kind") != "Service":
      log.warn("Did not get service: %s" % r) 
      return None
    if r.get("metadata", {}).get("name") != service_name:
      log.warn("Did not get service with desired name: %s" % r)
      return None
      
    clusterIP = r.get("spec", {}).get("clusterIP")

    if not clusterIP:
      log.warn("Service not found: " + service_name)
    
    self._get_service_ip_cache[service_name] = clusterIP
    return clusterIP
  
  def wait_for_pod(self, pod_name, max_wait_sec=300):
    log.info("Waiting for pod " + pod_name + " ...")
      
    kubectl = os.path.join(self.opts.k8s_path, "cluster/kubectl.sh")
    running = False
    waited = 0
    while not running:
      r = self.run_and_get_json(kubectl + " get pod " + pod_name + " -o json")
      log.debug("k8s response: %s" % r)
            
      conds = r.get("status", {}).get("conditions", [])
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
      self.run_in_k8s("./cluster/kubectl.sh describe pod " + pod_name)
      self.run_in_k8s("./cluster/kubectl.sh log " + pod_name)
      return False
    
    log.info("... pod " + pod_name + " up!")
    return True
  
  def get_docker_private_registry(self):
    return self.get_service_ip("gpg-local-registry")
  
  def push_to_remote_docker_registry(self, tag, reg_host=None):
    if not reg_host:
      reg_host = self.get_docker_private_registry()
    
    self.run_in_shell("docker tag -f " + tag + " " + reg_host + ":5000/" + tag)
    self.run_in_shell("docker push " + reg_host + ":5000/" + tag)
  
  def buildbox_push_to_private_reg(self, tag):
    reg_host = self.get_docker_private_registry()
    self.exec_in_buildbox("docker tag -f " + tag + " " + reg_host + ":5000/" + tag)
    self.exec_in_buildbox("docker push " + reg_host + ":5000/" + tag)
  
  def buildbox_docker_build(self, remote_path, tag):
    self.exec_in_buildbox(
      'sh -c "cd ' + remote_path + ' && docker build -t ' + tag + ' ."')
  
  def create_custom_buildbox(self, bbox_dockerfile_path, name):
    log.info("Creating custom buildbox Dockerfile ...")
    outpath = bbox_dockerfile_path + ".buildbox"
    self.exec_in_buildbox(
      # Use sh -c so > gets run on remote machine
      # We're running: cd gridpg && ctl.py --xlate path > outpath 
      'sh -c "' +
        'cd /opt/GridPG/ && ' +
        './ctl.py ' +
        '--xlate-to-custom-buildbox ' + bbox_dockerfile_path +
        ' > ' + outpath + '"') 
    
    workdir, dfilename = os.path.split(outpath)
    self.exec_in_buildbox(
      'sh -c "cd ' + workdir + ' && ' +
             'docker build -t ' + name + ' -f ' + dfilename + ' ."')
    self.buildbox_push_to_private_reg(name)
    
    PODSPEC = """
      apiVersion: v1
      kind: Pod
      metadata:
       name: %%name%%
       labels:
        name: %%name%%
      spec:
        containers:
        - name: %%name%%
          image: %%dpr%%/%%name%%
          securityContext:
            privileged: true
          ports:
          - name: ssh
            containerPort: 22
            hostPort: 30022
            protocol: TCP
          volumeMounts:
            - name: dockersock
              mountPath: /var/run/docker.sock
        volumes:
          - name: dockersock
            hostPath:
              path: /var/run/docker.sock
    """
  
    spec = str(PODSPEC)
    spec = spec.replace("%%name%%", name)
    private_registry = self.get_docker_private_registry()
    spec = spec.replace("%%dpr%%", private_registry + ":5000")
    
    kubectl = os.path.join(self.opts.k8s_path, "cluster/kubectl.sh")
    cmd = kubectl + " create -f -"
    self.run_with_stdin(cmd, spec)
    
   
  
  ###
  ### Buildbox SSH
  ###
  
  # NB: We use a custom port so as to not interfere with host / k8s ssh
  SSH_PORT = "30022"
  SSH_KEY_PATH = "/root/.ssh/id_dsa_gpg_buldbox_ssh"
  SSH_KEY_PUB_PATH = "/root/.ssh/id_dsa_gpg_buldbox_ssh.pub"
  
  def buildbox_enable_ssh(self, pod="gpg-buildbox"):
    self.log.info("Setting up ssh on buildbox ...")
    
    created_new_keys = False
    if not os.path.exists(self.SSH_KEY_PATH):
      log.info("... generating new ssk key for buildbox ...")
      self.run_in_shell("ssh-keygen -t dsa -P '' -f " + self.SSH_KEY_PATH)
      log.info("... authorizing locally ...")
      self.run_in_shell("/opt/accept_gpg_sshfs_key.sh")
      created_new_keys = True
    
    has_keys = False
    if not created_new_keys:
      try:
          #k8s does not propagate the exit code correctly, so we use false 
        self.exec_in_buildbox(
          'ls -lhat ' + self.SSH_KEY_PATH + ' || false',
          pod=pod)
        self.exec_in_buildbox(
          'ls -lhat ' + self.SSH_KEY_PUB_PATH + ' || false',
          pod=pod)
        has_keys = True
        log.info(
          "... buildbox already has keys; to re-install "
          "rm -rf /root/.ssh/id_dsa_gpg_sshfs* in buildbox machine "
          "...")
      except Exception:
        pass
      
    if not has_keys:
      log.info(
        "... installing ssh keys on buildbox (cmd will be redacted) ... ")
      self.exec_in_buildbox('mkdir -p /root/.ssh', pod=pod)
      for path in (self.SSH_KEY_PATH, self.SSH_KEY_PUB_PATH):
        content = open(path, 'r').read()
        # NB: we use sh -c to make the > redirect explicitly run *remotely*
        # NB: also, we use echo here because, sadly, cat | kubcetl -- tee
        # doesn't work-- it blocks indefinitely (looks like a Golang / k8s bug) 
        self.exec_in_buildbox(
          'sh -c "echo \'' + content +  '\' > ' + path + ' "',
          pod=pod,
          redacted=True)
      
      log.info("... authorizing copied key and bouncing sshd ...")
      self.exec_in_buildbox('/opt/accept_gpg_sshfs_key.sh', pod=pod)
    
    # TODO: can we make this provider agnostic eventually?
    if self.opts.provider == "gce":
      RULE_NAME = "gpg-buildbox-ssh"
      rule_exists = False
      resp = self.run_and_get_json(
        "gcloud compute firewall-rules list --format json")
      for rule in resp:
        if rule.get("name") == RULE_NAME:
          rule_exists = True
          break
      if not rule_exists:
        log.info("... adding firewall rule to open ssh ...")
        self.run_in_shell(
          "gcloud compute firewall-rules create " + RULE_NAME +
          " --allow=tcp:" + self.SSH_PORT)
    elif self.opts.provider == "aws":
      assert False, "TODO TODO TODO"
    else:
      log.warn(
        "Don't know how to add firewall rule for provider " +
        self.opts.provider)  
    
    log.info("... testing ssh ...")
    BUILDBOX_HOST = self.get_pod_host(pod)
    SSH_CMD_BASE = (
      "ssh -o StrictHostKeyChecking=no " + BUILDBOX_HOST + " " +
      "-p " + self.SSH_PORT + " " +
      "-i " + self.SSH_KEY_PATH + " ")
    self.run_in_shell(SSH_CMD_BASE + "uptime")
    
    self.log.info("... ssh available!")
  
  def buildbox_sshfs_remote_mount(
                  self,
                  local_path,
                  remote_path=None,
                  pod="gpg-buildbox"):
    
    if not remote_path:
      remote_path = local_path
    
    self.buildbox_enable_ssh(pod=pod)
    log.info("Mounting " + local_path + " to remote buildbox via sshfs ...")
      
    log.info("... starting tunneled sshfs ...")
    # We must create an empty directory for the mounted file system
    # or sshfs will crash. 
    try:
      # Try to clean up after a previous sshfs attempt
      self.exec_in_buildbox("umount " + remote_path, pod=pod)
    except Exception:
      pass
    self.exec_in_buildbox("mkdir -p " + remote_path, pod=pod)
    BUILDBOX_HOST = self.get_pod_host(pod)
    SSH_CMD_BASE = (
      "ssh -o StrictHostKeyChecking=no " + BUILDBOX_HOST + " " +
      "-p " + self.SSH_PORT + " "
      "-i " + self.SSH_KEY_PATH + " ")
    self.run_in_shell(
      SSH_CMD_BASE +
      # Forward local SSH_PORT remotely as port 9900
      "-nT -R 9900:localhost:" + self.SSH_PORT +
      # Have remote host sshfs back to our local machine through the
      # forwarded 30020 port.  Use our special purpose ssh key.
      " -- sshfs -p 9900 -oIdentityFile=" + self.SSH_KEY_PATH + " " +
      "-oStrictHostKeyChecking=no " +
      # Tell sshfs to mount `local_path` (read from the forwarded 30020 port)
      # to `remote_path` on the remote host
      "localhost:" + local_path + " " + remote_path +" &")
    
    log.info("... testing remote mount ...")
    self.exec_in_buildbox("ls -lhat " + remote_path, pod=pod)
    
    log.info("... local path mounted remotely! Done!!")
  
  
  ###
  ### Actions
  ###
  
  @staticmethod
  def load_from(opts):
    """Load and instantiate a ClusterContext from ctl.py `opts`"""
    dir_path = opts.cluster
    c = ClusterContext.load_clusterdef_from(dir_path)
    if hasattr(c, 'use_default_base') and c.use_default_base:
      base_c = ClusterContext.load_clusterdef_from(DEFAULT_BASE_CLUSTER_PATH)
      c = ComposedClusterDef([base_c, c])
    
    return ClusterContext(c, opts)
  
  @staticmethod
  def load_clusterdef_from(dir_path):
    assert os.path.exists(dir_path), "No cluster directory: %s" % dir_path
    f, fname, desc = imp.find_module("gpg_cluster_def", [dir_path])
    try:
      gpg_cluster_def = imp.load_module("gpg_cluster_def", f, fname, desc)
      log.info("Loaded cluster from %s" % dir_path)
    finally:
      f.close()
    
    return gpg_cluster_def.Cluster()
  
  def run(self):
    if self.opts.up:
      self.opts.before_up = True
      self.opts.k8s_up = True
      self.opts.create_entities = True
      self.opts.after_up = True
      self.opts.test_cluster = True

    if self.opts.before_up:
      if hasattr(self.c, "before_up"):
        log.info("Running cluster setup ...")
        self.c.before_up(self)
        log.info("... done.")
    
    if self.opts.k8s_up:
      env = {"KUBERNETES_PROVIDER": self.opts.provider}
      if hasattr(self.c, "k8s_up_env"):
        env.update(self.c.k8s_up_env(self))
      cmd = " ".join(k + "=" + v for (k, v) in env.iteritems())
      cmd += " ./cluster/kube-up.sh"
      log.info("Starting cluster ...")
      self.run_in_k8s(cmd)
      log.info("... done.")
     
    if self.opts.create_entities:
      log.info("Creating k8s entities ...")
      k8s_defs = []
      if hasattr(self.c, "k8s_create_defs"):
        k8s_defs += self.c.k8s_create_defs(self)
      for path in k8s_defs:
        self.run_in_k8s("./cluster/kubectl.sh create -f " + path)
      log.info("... done.")

    if self.opts.after_up:
      if hasattr(self.c, "after_up"):
        log.info("Running post-cluster setup ...")
        self.c.after_up(self)
        log.info("... done.")

    if self.opts.test_cluster:
      if hasattr(self.c, "test_cluster"):
        log.info("Running cluster tests ...")
        self.c.test_cluster(self)
        log.info("... done.")

    if self.opts.in_remote_buildbox:
      self.buildbox_enable_ssh()
      BUILDBOX_HOST = self.get_pod_host("gpg-buildbox")
      cmd = (
        "ssh -o StrictHostKeyChecking=no " + BUILDBOX_HOST +
        " -p " + self.SSH_PORT +
        " -i " + self.SSH_KEY_PATH)
      log.info("Dropping remote shell: " + cmd)
      os.execvp("ssh", cmd.split(" "))

    if self.opts.down:
      self.run_in_k8s("./cluster/kube-down.sh")
  
  
  
  
    
    
    # TODO fixme
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
    "--cluster", default=DEFAULT_BASE_CLUSTER_PATH,
    help="Path to cluster files [default %default]")
  config_group.add_option(
    "--adminbox-tag", default="gpg-adminbox",
    help="Give the adminbox image this tag [default %default]")
  config_group.add_option(
    "--buildbox-tag", default="gpg-buildbox",
    help="Give the buildbox image this local tag [default %default]")
  config_group.add_option(
    "--buildbox-image", default="gridpgadmin/gpg-buildbox",
    help="Push/pull this (official) buildbox image [default %default]")
  config_group.add_option(
    "--registry", default=None,
    help="Use this docker registry host. By default, use the cluster's "
         "private registry.")
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
  local_group.add_option(
    "--interactive", default=False, action="store_true",
    help="Drop into an interactive python session after running all other "
         "actions")
  local_group.add_option(
    "--xlate-to-custom-buildbox", default=None,
    help="Given a path to a Dockerfile or Dockerfile on stdin (pass '-'), "
         "emit on stdout Dockerfile that can be used to create a "
         "buildbox-compatible container.")
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
    help="Bring the cluster up.  Equivalent to "
         "--before-up --k8s-up --create-entities --after-up --test-cluster")
  cluster_group.add_option(
    "--before-up", default=False, action="store_true",
    help="Run some actions before bringing up k8s")
  cluster_group.add_option(
    "--k8s-up", default=False, action="store_true",
    help="Bring up (base) k8s")
  cluster_group.add_option(
    "--create-entities", default=False, action="store_true",
    help="Bring up any k8s entities associated with the cluster "
         "(e.g. pods, services)")
  cluster_group.add_option(
    "--after-up", default=False, action="store_true",
    help="Run any post-creation actions (e.g. build steps)")
  cluster_group.add_option(
    "--test-cluster", default=False, action="store_true",
    help="Test the completed cluster")
  cluster_group.add_option(
    "--down", default=False, action="store_true",
    help="Destroy the cluster")
  cluster_group.add_option(
    "--in-remote-buildbox", default=False, action="store_true",
    help="SSH to the buildbox and drop into a bash shell.  "
         "(Requires a running cluster)")
  option_parser.add_option_group(cluster_group)
  
  # -- Try adding --privileged to k8s conig (or CAP for mounting so DID works?)
  #     and see if we can run adminbox in k8s.  see if we can DID build
  #     containers and push to k8s repo (will require insecure-reg inside docker)
  #       Then we can have a build box, and write things to run inside it;
  #       expose the  destination reg thru ENV or use the K8S env.  Even
  #       run Travis??!  
  # -- add reg repo to use.  gridpg will commit tags to that repo
  # -- add --insecure-reg to the master machine's docker.  
  # -- TODO deleteme
  
  opts, args = option_parser.parse_args()
  
  
  
  assert os.path.exists("LICENSE"), "Please run from root of a GridPG distro"
  
  # Meta-opts
  if opts.build_and_admin:
    opts.deps = True
    opts.buildbox_build = True
    opts.adminbox_build = True
    opts.in_adminbox = True
  
  if opts.deps:
    # Pull git friends
    run_in_shell("git submodule update --init")

    # Build k8s
    K8S_TAR = "deps/kubernetes/_output/release-tars/kubernetes.tar.gz"
    if not os.path.exists(K8S_TAR):
      run_in_shell("cd deps/kubernetes && make quick-release")
      log.info(
        "Nota bene: the k8s build process may leave behind some large "
        "(and dangling) docker images.  Run "
        "  docker rmi $(docker images -f \"dangling=true\" -q) "
        "to free up some disk space.")

  if opts.clean:
    run_in_shell("rm -rf deps/*")
  
  if opts.buildbox_build or opts.buildbox_build_and_push:
    run_in_shell("cd buildbox && docker build -t " + opts.buildbox_tag + " .")

  if opts.buildbox_build_and_push:
    # TODO: gpg docker account
    run_in_shell(
      "docker tag -f " + opts.buildbox_tag + " " + opts.buildbox_image + " && "
      "docker push " + opts.buildbox_image)
  
  if opts.adminbox_build:
    run_in_shell("cd adminbox && docker build -t " + opts.adminbox_tag + " .")

  if opts.adminbox_start or opts.in_adminbox:
    run_in_shell(
      "docker run -d --net=host --name=gpg-adminbox -p 30022:30022 " +
      "--privileged " +
      "-v " + os.path.abspath(".") + ":/opt/GridPG " +
      "-v " + os.path.abspath("deps/kubernetes") + ":/opt/kubernetes " +
      "-w /opt/GridPG " + opts.adminbox_tag)
#     log.info("Building k8s ...") TODO deleteme
#     run_in_shell("docker exec gpg-adminbox /opt/build_k8s.sh")
#     log.info("... done building k8s")
  
  if opts.in_adminbox:  
    docker_cmd = "docker exec -it gpg-adminbox bash"
    log.info("Dropping into shell: " + docker_cmd)
    os.execvp("docker", docker_cmd.split(" "))

  if opts.adminbox_rm:
    run_in_shell("docker kill gpg-adminbox && docker rm gpg-adminbox")

  if opts.xlate_to_custom_buildbox is not None:
    dockerfile_content = ""
    if opts.xlate_to_custom_buildbox == "-":
      dockerfile_content = sys.stdin.read()
    else:
      dockerfile_content = open(opts.xlate_to_custom_buildbox, 'r').read()
    
    lines = dockerfile_content.split("\n")
    for i in range(len(lines)):
      if lines[i].startswith("FROM"):
        lines[i] = "FROM " + opts.buildbox_image
      elif lines[i].startswith("CMD") or lines[i].startswith("ENTRYPOINT"):
        # Skip container's startup
        lines[i] = "" 
    
    # Use buildbox startup
    lines.append("CMD /opt/startup.sh")
    
    custom_dockerfile = "\n".join(lines)
    print >>sys.stdout, custom_dockerfile

  c = ClusterContext.load_from(opts)
  c.run()

  if opts.interactive:
    import code
    import readline
    import rlcompleter
    vars = globals()
    vars.update(locals())
    readline.set_completer(rlcompleter.Completer(vars).complete)
    readline.parse_and_bind("tab: complete")
    shell = code.InteractiveConsole(vars)
    shell.interact()
