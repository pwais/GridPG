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
 * Tested in Python 2.7
""")

LOG_FORMAT = "%(asctime)s\t%(name)-4s %(process)d : %(message)s"

if __name__ == "__main__":
  
  # Direct all script output to a log
  log = logging.getLogger("setup")
  log.setLevel(logging.INFO)
  console_handler = logging.StreamHandler(stream=sys.stderr)
  console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
  log.addHandler(console_handler)


  def run_in_shell(cmd):
    log.info("Running %s ..." % cmd)
    subprocess.check_call(cmd, shell=True)
    log.info("... done")
  
  
  # Flags! No, wait, they"re *options* ...
  option_parser = OptionParser(usage=USAGE)
  
  config_group = OptionGroup(
                    option_parser,
                    "Config",
                    "Configuration")
  config_group.add_option(
    "--tag", default="local_k8s",
    help="Use this image tag [default %default]")
  config_group.add_option(
    "--k8s", default=os.path.abspath("../deps/kubernetes"),
    help="Mount this distro of k8s inside the container")
  option_parser.add_option_group(config_group)
  
  action_group = OptionGroup(
                    option_parser,
                    "Local",
                    "Local Actions")
  action_group.add_option(
    "--build", default=False, action="store_true",
    help="Build the k8s container")
  action_group.add_option(
    "--test", default=False, action="store_true",
    help="Start up a test container")
  action_group.add_option(
    "--test-shell", default=False, action="store_true",
    help="Drop into bash inside the test container")
  action_group.add_option(
    "--rm", default=False, action="store_true",
    help="Remote the test container")
  option_parser.add_option_group(action_group)

  
  opts, args = option_parser.parse_args()
  
  
  assert os.path.exists("DOCKERFILE"), "Please run from local_k8s directory"
  
  if opts.build:
    run_in_shell("docker build -t " + opts.tag + " .")

  if opts.test:
    run_in_shell(
      "docker run --privileged=true -d --name=local_k8s_test -t " +
      "-v " + opts.k8s + ":/opt/kubernetes " + opts.tag)
  
  if opts.test_shell:
    CMD = "docker exec --interactive --tty local_k8s_test bash"
    os.execvp("docker", CMD.split(" "))

  if opts.rm:
    run_in_shell("docker kill local_k8s_test && docker rm local_k8s_test")
