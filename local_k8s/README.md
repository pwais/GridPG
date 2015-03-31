# Local k8s
A Docker container for running `kubernetes` locally.  Useful for testing
a cluster of containers before deploying to paid cloud service.

To use, run `$ ./setup.py --build`

# Testing the Container

1. Start a test container:

    ```$ ./setup.py --test```

It may take a minute or two for k8s to build inside the container.  Use `$ docker logs local_k8s_test` to follow along.  Wait until you see a message like:
  
  ```
  To start using your cluster, open up another terminal/tab and run:

  cluster/kubectl.sh config set-cluster local --server=http://127.0.0.1:8080 --insecure-skip-tls-verify=true --global
  cluster/kubectl.sh config set-context local --cluster=local --global
  cluster/kubectl.sh config use-context local
  cluster/kubectl.sh
  ```

2. Start a shell inside the container: 

    ```$ ./setup.py --test-shell```

3. Try running nginx.  First start nginx through k8s:

  ```
  % cd /opt/kubernetes
  % cluster/kubectl.sh run-container my-nginx --image=dockerfile/nginx --replicas=2 --port=80
  ```

Wait for k8s to deploy nginx.  Poll `% cluster/kubectl.sh get pods` until the pods' status is in the `Running` state.

Now see if you can see the nginx welcome page: `% curl http://10.0.0.2:80`

4. To remove the test cluster, use `$ ./setup.py --rm`

# References
* https://github.com/ghodss/kubernetes-macosx-development
* https://github.com/GoogleCloudPlatform/kubernetes/blob/master/docs/getting-started-guides/locally.md
* https://github.com/GoogleCloudPlatform/golang-docker/blob/master/base/Dockerfile
* https://github.com/jpetazzo/dind

