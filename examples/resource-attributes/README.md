# resource-attributes example

> Note to try this out with minikube, make sure you enable RBAC correctly as explained [here](../minikube-rbac).

RBAC differentiates in two types, that need to be authorized, resources and non-resoruces. A resource request authorization, could for example be, that a requesting entity needs to be authorized to perform the `get` action on a particular Kubernetes Deployment.

Take the following example. We want to deploy a [prometheus-example-app](https://github.com/brancz/prometheus-example-app), and protect it with the kube-rbac-proxy. In this example we require a requesting entity to be allowed to call the `proxy` subresource on a Kubernetes Service called `kube-rbac-proxy`. This is configured in the file passed to the kube-rbac-proxy with the `--config-file` flag. Additionally the `--upstream` flag has to be set to configure the application that should be proxied to on successful authentication as well as authorization.

The kube-rbac-proxy itself also requires RBAC access, in order to perform TokenReviews as well as SubjectAccessReviews. These are the APIs available from the Kubernetes API to authenticate and then validate the authorization of an entity.

```bash
$ kubectl create -f deployment.yaml
```

The content of this manifest is:

[embedmd]:# (./deployment.yaml)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-rbac-proxy
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy
subjects:
- kind: ServiceAccount
  name: kube-rbac-proxy
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy
rules:
- apiGroups: ["authentication.k8s.io"]
  resources:
  - tokenreviews
  verbs: ["create"]
- apiGroups: ["authorization.k8s.io"]
  resources:
  - subjectaccessreviews
  verbs: ["create"]
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: kube-rbac-proxy
  name: kube-rbac-proxy
spec:
  ports:
  - name: https
    port: 8443
    targetPort: https
  selector:
    app: kube-rbac-proxy
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-rbac-proxy
data:
  config-file.yaml: |+
    authorization:
      resourceAttributes:
        namespace: default
        apiVersion: v1
        resource: services
        subresource: proxy
        name: kube-rbac-proxy
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-rbac-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kube-rbac-proxy
  template:
    metadata:
      labels:
        app: kube-rbac-proxy
    spec:
      securityContext:
        runAsUser: 65532
      serviceAccountName: kube-rbac-proxy
      containers:
      - name: kube-rbac-proxy
        image: quay.io/brancz/kube-rbac-proxy:v0.23.1
        args:
        - "--secure-port=8443"
        - "--upstream=http://127.0.0.1:8081/"
        - "--config-file=/etc/kube-rbac-proxy/config-file.yaml"
        - "--logtostderr=true"
        - "--v=10"
        ports:
        - containerPort: 8443
          name: https
        volumeMounts:
        - name: config
          mountPath: /etc/kube-rbac-proxy
        securityContext:
          allowPrivilegeEscalation: false
      - name: prometheus-example-app
        image: quay.io/brancz/prometheus-example-app:v0.6.0
        args:
        - "--bind=127.0.0.1:8081"
      volumes:
      - name: config
        configMap:
          name: kube-rbac-proxy
```

Once the prometheus-example-app is up and running, we can test it. In order to test it, we deploy a Job, that performs a `curl` against the above deployment. Because it has the correct RBAC roles, the request will succeed.

The Dockerfile of this container can be found [here](../example-client/Dockerfile).

```bash
$ kubectl create -f client-rbac.yaml client.yaml
```

The content of this manifest is:

[embedmd]:# (./client-rbac.yaml)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy-client
rules:
- apiGroups: [""]
  resources: ["services/proxy"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kube-rbac-proxy-client
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-rbac-proxy-client
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
```

[embedmd]:# (./client.yaml)
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: krp-curl
spec:
  template:
    metadata:
      name: krp-curl
    spec:
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
      restartPolicy: Never
  backoffLimit: 4
```

We can look at the logs and we should get something similar to:

```
$ kubectl logs job/krp-curl
*   Trying 10.111.34.206...
* TCP_NODELAY set
* Connected to kube-rbac-proxy.default.svc (10.111.34.206) port 8080 (#0)
> GET /metrics HTTP/1.1
> Host: kube-rbac-proxy.default.svc:8080
> User-Agent: curl/7.57.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tNHZxZGIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImQwNzU4NDE3LWUzMmUtMTFlNy1hOTQ1LTA4MDAyNzg2NjgwMCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.eftzPb2rthIcW8Md4URFYpDhyEKuqepP7WKsWO25uBdWlN85TcPkeGSaRf7-dRp7ie5ADp-UgTZtI2lu6ssntmxsATeH_jE0zye6UlTqM-_2iLNLexgE29bYD8cqH5WMc7tE-y_Y0u0F3hjvURNvQycxfrGWICd1gNrk2jpxC6mAYVt3ldT5rylw0FWot7t8uDvorW6QScfvPPNmwh0hHsdvMuJ2e8lc9KDnTS-yRuQ1SmMNyc7L2JyZ7bphahNZNa8K7D3C1NOAmAQrDfBAr97peGbQ02yCc4hG_YQDyO2xMaQs_AFf38ZIiM-z7OnSQO4_D8FmkY2CG2jnd6ZXlw
>
< HTTP/1.1 200 OK
< Content-Type: text/plain; version=0.0.4
< Date: Sun, 17 Dec 2017 13:34:26 GMT
< Content-Length: 102
<
{ [102 bytes data]
* Connection #0 to host kube-rbac-proxy.default.svc left intact
# HELP version Version information about this binary
# TYPE version gauge
version{version="v0.1.0"} 0
```

