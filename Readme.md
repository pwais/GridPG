Test

* docker container that just runs k8s
* python reverse sshfs tunnel, python docker reg tunnel .. python ssh tunnel any port any minion ..


* config where ClusterPG runs k8s... should be in a container.  you should either run that container on your machine or ssh to machine
* ClusterPG runs itself in that container !  mount and copy options
* once there, ClusterPG will run your cluster up and down scripts, which probably just wrap k8s configs.  should run those scripts in a virtualenv with cpg lib code available...

