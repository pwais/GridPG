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
  
  
  # Flags! No, wait, they're *options* ...
  option_parser = OptionParser(usage=USAGE)
  
  config_group = OptionGroup(
                    option_parser,
                    "Config",
                    "Configuration")
  config_group.add_option(
    '--cluster', default=os.path.abspath('default_cluster'),
    help="Path to cluster files [default %default]")
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

    # Build k8s
    if not os.path.exists('deps/kubernetes/_output'):
      run_in_shell(
        "cd deps/kubernetes && make quick-release")

  if opts.clean:
    run_in_shell("rm -rf deps/kubernetes/_output")


