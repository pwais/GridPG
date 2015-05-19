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

LOG_FORMAT = '%(asctime)s\t%(name)-4s %(process)d : %(message)s'

class BaseCluster(object):
  
  gpg_base_path = os.path.abspath('.')
  
  log = logging.getLogger('cluster')
  log.setLevel(logging.INFO)
  console_handler = logging.StreamHandler(stream=sys.stderr)
  console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
  log.addHandler(console_handler)
  
  def __init__(self, c_cls, gpg_cluster_path=None):  
    self.gpg_cluster_path = gpg_cluster_path
    c = c_cls()
    
    if hasattr(c, "before_up"):
      self.before_up = c.before_up 
  
    self.c = c
#     if hasattr(c, "k8s_create_defs"):
#       self.k8s_create_defs = c.k8s_create_defs
  
  ### Utils
  
  def run_in_shell(cmd):
    log.info("Running %s ..." % cmd)
    subprocess.check_call(cmd, shell=True)
    log.info("... done")
  
  def gpg_path(self, path):
    return os.path.join(self.gpg_base_path, path)
  
  def cluster_path(self, path):
    return os.path.join(self.gpg_cluster_path, path)
  
  ### Interface
  
  def before_up(self):
    pass
  
  def k8s_up_env(self):
    pass
  
  def after_up(self):
    pass
  
  def k8s_create_defs(self):
    if hasattr(self.c, 'k8s_create_defs'):
      return self.c.k8s_create_defs(self)  # OK!!!
    else:
      return "moof"
  
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
    
    return BaseCluster(gpg_cluster_def.Cluster, gpg_cluster_path=dir_path)
    
      


if __name__ == '__main__':
  
  # Direct all script output to a log
  log = logging.getLogger('ctl')
  log.setLevel(logging.INFO)
  console_handler = logging.StreamHandler(stream=sys.stderr)
  console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
  log.addHandler(console_handler)

  def run_in_shell(cmd):
    log.info("Running %s ..." % cmd)
    subprocess.check_call(cmd, shell=True)
    log.info("... done")
  
  def get_cluster_class(cluster_dir):
#     assert os.path.exists(path), "Cluster file does not exist: %s" % path
    f, filename, description = imp.find_module("gpg_cluster_def", [cluster_dir])
    cluster_class = None
    try:
      cluster_class = imp.load_module("Cluster", f, filename, description)
      log.info("Loaded cluster %s from %s" % (cluster_class, cluster_dir))
    finally:
      f.close()
    return cluster_class  
  
  
  # Flags! No, wait, they're *options* ...
  option_parser = OptionParser(usage=USAGE)
  
  config_group = OptionGroup(
                    option_parser,
                    "Config",
                    "Configuration")
  config_group.add_option(
    '--cluster', default=os.path.abspath('clusters/base_dev_cluster'),
    help="Path to cluster files [default %default]")
  config_group.add_option(
    '--adminbox-tag', default="gpg-adminbox",
    help="Give the adminbox image this tag [default %default]")
  option_parser.add_option_group(config_group)
  
  local_group = OptionGroup(
                    option_parser,
                    "Local",
                    "Local Actions")
  local_group.add_option(
    '--deps', default=False, action='store_true',
    help="Set up local dependencies")
  local_group.add_option(
    '--clean', default=False, action='store_true',
    help="Clean local dependencies")
  local_group.add_option(
    '--adminbox-build', default=False, action='store_true',
    help="Set up local dependencies")
  option_parser.add_option_group(local_group)
  
  cluster_group = OptionGroup(
                    option_parser,
                    "Cluster",
                    "Cluster Actions")
  cluster_group.add_option(
    '--up', default=False, action='store_true',
    help="")
  option_parser.add_option_group(cluster_group)
  
  opts, args = option_parser.parse_args()
  
  
  
  assert os.path.exists('LICENSE'), "Please run from root of a GridPG distro"
  
  
  
  if opts.deps:
    # Pull git friends
    run_in_shell("git submodule update --init")

#     # Build k8s
#     if not os.path.exists('deps/kubernetes/_output'):
#       run_in_shell(
#         "cd deps/kubernetes && make quick-release")

  if opts.clean:
    run_in_shell("rm -rf deps/*")
  
  if opts.adminbox_build:
    run_in_shell("cd adminbox && docker build -t " + opts.adminbox_tag + " .")

  if opts.up:
    c = BaseCluster.load_from(opts.cluster)
    print c.k8s_create_defs()
