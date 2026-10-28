# Static Authorization example

> Note to try this out with minikube, make sure you enable RBAC correctly. Since minikube v0.26.0 the default bootstrapper is kubeadm - which should enable RBAC by default. For older version follow the instructions [here](../minikube-rbac).

RBAC differentiates in two types, that need to be authorized, resources and non-resources. A resource request authorization, could for example be, that a requesting entity needs to be authorized to perform the `get` action on a particular Kubernetes Deployment.

In this example we deploy the [prometheus-example-app](https://github.com/brancz/prometheus-example-app) and want to protect it with kube-rbac-proxy, just as detailed in the [rewrite example](../rewrite/README.md). In this example however we will avoid the recurring SubjectAccessReview requests to the api server by allowing kube-rbac-proxy to authorize these requests statically. This is configured in the file passed to the kube-rbac-proxy with the `--config-file` flag. Additionally the `--upstream` flag has to be set to configure the application that should be proxied to on successful authentication as well as authorization.

The kube-rbac-proxy itself also requires RBAC access, in order to perform TokenReviews as well as SubjectAccessReviews for requests that are not statically athorized. These are the APIs available from the Kubernetes API to authenticate and then validate the authorization of an entity.

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
      rewrites:
        byQueryParameter:
          name: "namespace"
      resourceAttributes:
        apiVersion: v1
        resource: namespace
        subresource: metrics
        namespace: "{{ .Value }}"
      static:
        - resourceRequest: true
          resource: namespace
          subresource: metrics
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

```bash
$ kubectl create -f client-rbac.yaml
```

The content of this manifest is:

[embedmd]:# (./client-rbac.yaml)
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: namespace-metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: namespace-metrics
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: namespace-metrics
rules:
- apiGroups: [""]
  resources:
  - namespace/metrics
  verbs: ["get"]
```

Now simply run
```
kubectl run -i -t alpine --image=alpine --restart=Never -- sh -c 'apk add curl; curl -v -s -k -H "Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`" https://kube-rbac-proxy.default.svc:8443/metrics?namespace=default'
```

A configuration setting for the static authorization feature for resource requests looks like this:
```
  config-file.yaml: |+
    authorization:
      static:
        - user:
            name: UserName
            groups:
              - group1
              - group2
          verb: get
          namespace: default
          apiGroup: apps
          resourceRequest: true
          resource: namespace
          subresource: metrics
```

A configuration setting for the static authorization feature for non-resource requests looks like this:
```
  config-file.yaml: |+
    authorization:
      static:
        - user:
            name: UserName
            groups:
              - group1
              - group2
          verb: get
          resourceRequest: false
          path: /metrics
```

The values in the above example are just aimed at illustrating what is possible. An omitted configuration setting is interpreted as a wildcard. E.g. if a static-auth configuration omits the `user` setting, any user can be statically authorized if a request fits the remaining configuration.
