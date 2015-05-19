# Local k8s
A Docker container for running `kubernetes` locally via docker-in-docker.  Useful
for testing a cluster of containers before deploying to paid cloud service.

To use, run `$ ./dk8s.py --build && ./dk8s.py --up && ./dk8s.py --shell`

# Using the Container

1. Build the dk8s image:

	```$ ./dk8s.py --build```

It may take a minute or two for k8s to compile.  

2. Start up a dk8s instance:

	```$ ./dk8s.py --up```

Follow along (and look for errors) using `$ docker logs dk8s`.

3. Log in to the instance:

    ```$ ./dk8s.py --shell```
    
Optional: try running nginx.  First start nginx through k8s:

  ```
  % cd /opt/kubernetes
  % cluster/kubectl.sh run-container my-nginx --image=nginx --replicas=2 --port=80
  ```

Wait for k8s to deploy nginx.  Poll `% cluster/kubectl.sh get pods` until the pods' status is in the `Running` state.

Now see if you can see the nginx welcome page: `% curl http://10.0.0.2:80`
or `lynx http://10.0.0.2:80`
    
4. Finally, you can kill the container using `$ ./dk8s.py --rm`

# Troubleshooting

Docker-in-docker is prone to ip loopback device exhaustion.  We try to ameliorate
the issue by creating more loops in `startup.sh`, but you might still see
the inner docker daemon fail to start (with message "no more loopback devices" 
in `/var/log/docker.log`).  Try cleaning up your host's docker environment:
delete old (stopped) containers (e.g. ``` docker rm `docker ps --no-trunc -aq` ```),
restart your host's docker daemon, or restart boot2docker (e.g. if you're using OSX).

There was a prior issue where Kubernetes and Docker may try to claim IP addresses in the
same range.  In that case, you may need to edit `.kubernetes/hack/local-up-cluster.sh` to use `--portal_net="10.100.0.0/16"` as noted
in [the k8s docs](https://github.com/GoogleCloudPlatform/kubernetes/blob/master/docs/getting-started-guides/locally.md#i-cant-reach-service-ips-on-the-network) and 
then rebuild the dk8s container using `./dk8s.py --build`.

# References
* https://github.com/ghodss/kubernetes-macosx-development
* https://github.com/GoogleCloudPlatform/kubernetes/blob/master/docs/getting-started-guides/locally.md
* https://github.com/GoogleCloudPlatform/golang-docker/blob/master/base/Dockerfile
* https://github.com/jpetazzo/dind

