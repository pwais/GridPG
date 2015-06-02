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
    ctx.run_in_shell("cp -v " + ctx.cluster_path("kube_config.sh") + " " + config_dest)
  
  @staticmethod
  def k8s_up_env(ctx):
    return {
      "KUBE_CONFIG_FILE": "gpg-config.sh",
    }
  
  @staticmethod
  def k8s_create_defs(ctx):
    return (
      # Use base buildbox
      ctx.gpg_path("k8s_specs/docker-private-registry.yaml"),
      ctx.gpg_path("k8s_specs/docker-private-registry-service.yaml"),
      ctx.gpg_path("k8s_specs/gpg-buildbox.yaml"))
  
  @staticmethod
  def after_up(ctx):
    ctx.buildbox_sshfs_remote_mount("/opt/GridPG", "/opt/GridPG")
    
    ctx.log.info("Building CassieVede ...")
    ctx.buildbox_docker_build(ctx.cluster_path("cv_cassandra"), "cv_cassandra")
    ctx.buildbox_docker_build(ctx.cluster_path("cv_spark"), "cv_spark")
    ctx.buildbox_push_to_private_reg("cv_spark")
    ctx.buildbox_push_to_private_reg("cv_cassandra")
    ctx.log.info("... done building.")
    
    ctx.log.info("Starting CassieVede in k8s ...")
    cv_def_paths = (
      ctx.cluster_path("spark-master.yaml"),
      ctx.cluster_path("spark-master-service.yaml"),
      ctx.cluster_path("cv-controller.yaml"),
#       ctx.cluster_path("cv.yaml"), TODO do we need this?
      ctx.cluster_path("cv-service.yaml"))
    for path in cv_def_paths:
      ctx.run_in_k8s("./cluster/kubectl.sh create -f " + path)
    ctx.log.info("... created k8s components ...")
    
    # TODO: check service health
