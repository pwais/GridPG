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
  
  use_default_base = True
  
  @staticmethod
  def before_up(ctx):
    cass_k8s_jar_path = os.path.join(
                          ctx.opts.k8s_path,
                          "examples/cassandra/image/kubernetes-cassandra.jar")
    cv_k8s_jar_dest = ctx.cluster_path("cv_cassandra/kubernetes-cassandra.jar")
    ctx.log.info("Using k8s cassandra support")
    ctx.run_in_shell("cp -v " + cass_k8s_jar_path + " " + cv_k8s_jar_dest)
  
  @staticmethod
  def k8s_up_env(ctx):
    return {}
  
  @staticmethod
  def k8s_create_defs(ctx):
    return tuple()
  
  @staticmethod
  def after_up(ctx):
    ctx.log.info("Building CassieVede services ...")
    ctx.buildbox_docker_build(ctx.cluster_path("cv_cassandra"), "cv_cassandra")
    ctx.buildbox_docker_build(ctx.cluster_path("cv_spark"), "cv_spark")
    ctx.buildbox_push_to_private_reg("cv_spark")
    ctx.buildbox_push_to_private_reg("cv_cassandra")
    ctx.log.info("... done building.")
    
    ctx.log.info("Starting CassieVede in k8s ...")
    cv_def_paths = (
      ctx.cluster_path("spark-master.yaml"),
      ctx.cluster_path("spark-master-service.yaml"),
      ctx.cluster_path("cv-service.yaml"),
      ctx.cluster_path("cv-controller.yaml"),
#       ctx.cluster_path("cv.yaml"), TODO do we need this?
      )
    for path in cv_def_paths:
      ctx.run_k8s_templated_create_def(path)
    ctx.log.info("... done creating k8s components.")
    
    
    # It looks like we'll prolly want a pod to admin cassievede.  that or start its container in k8s
#     ctx.log.info("... created k8s components ...")
    
  @staticmethod
  def test_cluster(ctx):
    kubectl = os.path.join(ctx.opts.k8s_path, "cluster/kubectl.sh")
    
    ctx.log.info("Checking for cv pods ...")
    r = ctx.run_and_get_json(
          kubectl + " get pods -l name=cv -o json")
    cv_pods = r.get("items", [])
    assert cv_pods, "No cv pods started!"
    pod = cv_pods[0]
    pod_name = pod["metadata"]["name"]
    ctx.log.info("Waiting for pod " + pod_name + " to start ...")
    ctx.get_pod(pod_name, wait=True, use_cache=False)
    
    ctx.log.info("Checking Cassandra connectivity ...")
    ctx.run_in_shell(
      kubectl + " exec " + pod_name + " -c cassandra -- nodetool status")
    
    ctx.log.info("Testing Spark ...")
    ctx.run_in_shell(kubectl + " exec spark-master -- /test-pi.sh")
