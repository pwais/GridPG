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

import os

class Cluster(object):
  
  @staticmethod
  def before_up(ctx):
    config_dest = os.path.join(ctx.opts.k8s_path, "cluster/gce/gpg-config.sh")
    ctx.log.info("Installing cluster config:")
    ctx.run_in_shell(
      "cp -v " + ctx.gpg_path("k8s_specs/kube_config.sh") + " " + config_dest)
  
  @staticmethod
  def k8s_up_env(ctx):
    return {
      "KUBE_CONFIG_FILE": "gpg-config.sh",
    }
  
  @staticmethod
  def k8s_create_defs(ctx):
    return (
      ctx.gpg_path("k8s_specs/gpg-buildbox.yaml"),
      ctx.gpg_path("k8s_specs/gpg-local-registry-service.yaml"),)
  
  
  @staticmethod
  def after_up(ctx):
    ctx.buildbox_sshfs_remote_mount("/opt/GridPG", "/opt/GridPG")
  
  @staticmethod
  def test_cluster(ctx):
    ctx.log.info("Checking GridPG remote mount:")
    ctx.exec_in_buildbox("ls -lhat /opt/GridPG/LICENSE")
    
    ctx.log.info("Checking docker private registry:")
    ctx.log.info("IP: " + ctx.get_docker_private_registry())
    
