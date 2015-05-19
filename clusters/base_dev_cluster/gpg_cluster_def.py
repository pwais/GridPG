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

class Cluster(object):
  
  def before_up(self):
    print "moof!!"
  
  def k8s_up_env(self):
    return {
      "moof": "moooof"
    }
  
  @staticmethod
  def k8s_create_defs(c):
    return (
      c.gpg_path("k8s_specs/docker-private-registry.yaml"),
      c.gpg_path("k8s_specs/docker-private-registry-service.yaml"),
    )
    
  def after_up(self):
    print "moooof!"
