#!/bin/bash                                                                                                                                                                            

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

set -o errexit
set -o nounset
set -o pipefail
set -x

# Keys exist, right?
ls -lhat /root/.ssh/id_dsa_gpg_sshfs
ls -lhat /root/.ssh/id_dsa_gpg_sshfs.pub

chmod 600 /root/.ssh/id_dsa_gpg_sshfs
chmod 600 /root/.ssh/id_dsa_gpg_sshfs.pub

cat /root/.ssh/id_dsa_gpg_sshfs.pub > /root/.ssh/authorized_keys

echo "AuthorizedKeysFile /root/.ssh/authorized_keys" >> /etc/ssh/sshd_config
service ssh restart

