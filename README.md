(Old / abandoned / for reference)

TODO: finish

## Providers

### Local

Use `dk8s` (todo more docs)

### GCE


gcloud compute instances create gpg-deploy-host --image container-vm-v20150505 


```$ gcloud auth login```
```$ gcloud config set project PROJECT_ID```

Make sure GCE is enabled for your project; in the GCE Web Console, click on
Compute > Compute Engine > VM instances to force-enable GCE for the project.

* start a gce cluster with docker reg in gce
* run a test of pushing an image to the docker reg
* figure out sshfs tunnel
* create cassievede cluster and test loading stuff


## Nota Bene: Tips & Tricks

### Mount Local Directory on Remote Deploy Machine


Forward the ssh port on your machine to the remote machine's port 9000:

```$ ssh -nNT -R 9000:localhost:22 deploy-username@deploy-host```

(and enter your deploy machine password).  SSH to the `deploy-host` and run:

```$ sshfs -p 9000 user@localhost:/path/on/your/machine /mnt/path/on/remote```

(and enter your *local* machine password).  If you need to mount a local
directory to *many* remote machines, or set up this remote mount in a more
automated way, you might consider generating a passwordless ssh key for
your local machine and distributing it to the remote machines.  FMI try:
 * https://help.ubuntu.com/community/SSH/OpenSSH/Keys
 * https://help.github.com/articles/generating-ssh-keys/
 * http://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html




* docker container that just runs k8s
* python reverse sshfs tunnel, python docker reg tunnel .. python ssh tunnel any port any minion ..


* config where ClusterPG runs k8s... should be in a container.  you should either run that container on your machine or ssh to machine
* ClusterPG runs itself in that container !  mount and copy options
* once there, ClusterPG will run your cluster up and down scripts, which probably just wrap k8s configs.  should run those scripts in a virtualenv with cpg lib code available...



