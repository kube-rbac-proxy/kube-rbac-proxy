# non-resource-url-token-request example

> Token audience reviews can be combined with any of the other features of kube-rbac-proxy, such as reviewing permission for specific resources, this example merely chooses to show the functionality using a non-resource-url permission.

This examples is in essence similar to the [non-resource-url](../non-resource-url/) example, with the key difference, that this example requires the ServiceAccount token sent by a client must be scoped to the `kube-rbac-proxy.default.svc` audience. In this example the scoped ServiceAccount token is obtained via a projected volume and mounted into the client container from where it can be consumed. The reasoning here is that scoped tokens cannot be used to impersonate an entity by re-using the token to perform a request against the Kubernetes API itself.

The audience a token must be scoped to is configured within the kube-rbac-proxy using the `--auth-token-audiences` flag.
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
        - "--auth-token-audiences=kube-rbac-proxy.default.svc"
        - "--v=10"
        ports:
        - containerPort: 8443
          name: https
        securityContext:
          allowPrivilegeEscalation: false
      - name: prometheus-example-app
        image: quay.io/brancz/prometheus-example-app:v0.6.0
        args:
        - "--bind=127.0.0.1:8081"
```

Once the prometheus-example-app is up and running, we can test it. In order to test it, we deploy a Job, that performs a `curl` against the above deployment. Because it has the `/metrics` path in its `nonResourceURLs` it is allowed to access the endpoint.

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
  name: metrics
rules:
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: metrics
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
      restartPolicy: Never
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
        command:
        - /bin/sh
        - -c
        - 'curl -v -s -k -H "Authorization: Bearer `cat /service-account/token`" https://kube-rbac-proxy.default.svc:8443/metrics'
        volumeMounts:
        - name: token-vol
          mountPath: "/service-account"
          readOnly: true
      volumes:
      - name: token-vol
        projected:
          sources:
          - serviceAccountToken:
              audience: kube-rbac-proxy.default.svc
              expirationSeconds: 3600
              path: token
  backoffLimit: 4
```

We can look at the logs and we should get something similar to:

```
*   Trying 10.106.147.107...
* TCP_NODELAY set
* Connected to kube-rbac-proxy.default.svc (10.106.147.107) port 8443 (#0)
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: none
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
} [242 bytes data]
* TLSv1.2 (IN), TLS handshake, Server hello (2):
{ [49 bytes data]
* TLSv1.2 (IN), TLS handshake, Certificate (11):
{ [1649 bytes data]
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
{ [300 bytes data]
* TLSv1.2 (IN), TLS handshake, Server finished (14):
{ [4 bytes data]
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
} [37 bytes data]
* TLSv1.2 (OUT), TLS change cipher, Client hello (1):
} [1 bytes data]
* TLSv1.2 (OUT), TLS handshake, Finished (20):
} [16 bytes data]
* TLSv1.2 (IN), TLS change cipher, Client hello (1):
{ [1 bytes data]
* TLSv1.2 (IN), TLS handshake, Finished (20):
{ [16 bytes data]
* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=kube-rbac-proxy-695b54f7ff-z54b7@1579943520
*  start date: Jan 25 08:12:00 2020 GMT
*  expire date: Jan 24 08:12:00 2021 GMT
*  issuer: CN=kube-rbac-proxy-695b54f7ff-z54b7-ca@1579943520
*  SSL certificate verify result: self signed certificate in certificate chain (19), continuing anyway.
> GET /metrics HTTP/1.1
> Host: kube-rbac-proxy.default.svc:8443
> User-Agent: curl/7.61.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InBtUmFFQnJIUzJXS1RuR3FmcmRkRDd3TEM2NUx3STZmb29DczRNRGwzLXcifQ.eyJhdWQiOlsia3ViZS1yYmFjLXByb3h5LmRlZmF1bHQuc3ZjIl0sImV4cCI6MTU3OTk0NzYxMiwiaWF0IjoxNTc5OTQ0MDEyLCJpc3MiOiJrdWJlcm5ldGVzLmRlZmF1bHQuc3ZjIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJrcnAtY3VybC1nMjVweCIsInVpZCI6IjA3MWYxYzM1LWNmZWYtNGRhNy05ZjMxLWJiMmJkNmJmY2VmNyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjRlYzFiOWU4LTdkZmItNDhiNi1hMjU0LWFiYTg4MGJhZGY5ZiJ9fSwibmJmIjoxNTc5OTQ0MDEyLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpkZWZhdWx0In0.fM05SSlLzb5zMpTjYhn_H8Y0KFwX000VYqE8CMA3sP5lMAbXBInGSudbm_r_ppAMUYar6cmyAiSmIAD1bOR-DlzmJdX-LA5kgA3J9GAsrWBxXMlmASo1OfTjtOuQ98Y8tM6P-BCCe5rOAcx-ppmbPE_8Pu_7IkHjABURtClr6VUspsLfqsZ9GcN5pDBSR9iFt2Cl6m8YsbBXIDJ1kp9CknFt36s5Dg7OcTQR-WWkA21iZiOqayWGphW-DqpjEdm16XpjOqqDOf2qyFisjPhxNN-rivPJaCeoRb3GUIQVbvVShEgygzdM_8OqmZT3THeHBCdC_685Ffv3hFC4G6ijAQ
>
< HTTP/1.1 200 OK
< Content-Type: text/plain; version=0.0.4
< Date: Sat, 25 Jan 2020 09:20:12 GMT
< Content-Length: 102
<
{ [102 bytes data]
* Connection #0 to host kube-rbac-proxy.default.svc left intact
# HELP version Version information about this binary
# TYPE version gauge
version{version="v0.1.0"} 0
```

Whereas if we didn't use a token that was created for the correct audience, for example the default ServiceAccount token mounted into containers, then we should not be able to authenticate with that token. This can be verified with:


[embedmd]:# (./wrong-client.yaml)
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: krp-wrong-token-curl
spec:
  template:
    metadata:
      name: krp-wrong-token-curl
    spec:
      restartPolicy: Never
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
```

Then the log output should look something along the lines of:

```
*   Trying 10.106.147.107...
* TCP_NODELAY set
* Connected to kube-rbac-proxy.default.svc (10.106.147.107) port 8443 (#0)
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/ssl/certs/ca-certificates.crt
  CApath: none
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
} [242 bytes data]
* TLSv1.2 (IN), TLS handshake, Server hello (2):
{ [49 bytes data]
* TLSv1.2 (IN), TLS handshake, Certificate (11):
{ [1649 bytes data]
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
{ [300 bytes data]
* TLSv1.2 (IN), TLS handshake, Server finished (14):
{ [4 bytes data]
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
} [37 bytes data]
* TLSv1.2 (OUT), TLS change cipher, Client hello (1):
} [1 bytes data]
* TLSv1.2 (OUT), TLS handshake, Finished (20):
} [16 bytes data]
* TLSv1.2 (IN), TLS change cipher, Client hello (1):
{ [1 bytes data]
* TLSv1.2 (IN), TLS handshake, Finished (20):
{ [16 bytes data]
* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=kube-rbac-proxy-695b54f7ff-z54b7@1579943520
*  start date: Jan 25 08:12:00 2020 GMT
*  expire date: Jan 24 08:12:00 2021 GMT
*  issuer: CN=kube-rbac-proxy-695b54f7ff-z54b7-ca@1579943520
*  SSL certificate verify result: self signed certificate in certificate chain (19), continuing anyway.
> GET /metrics HTTP/1.1
> Host: kube-rbac-proxy.default.svc:8443
> User-Agent: curl/7.61.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InBtUmFFQnJIUzJXS1RuR3FmcmRkRDd3TEM2NUx3STZmb29DczRNRGwzLXcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbWtienYiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjRlYzFiOWU4LTdkZmItNDhiNi1hMjU0LWFiYTg4MGJhZGY5ZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.dWmmPOUTpIXve3svadwPd3a1PswkL8YC5JnPvul4EqQjcf-SLNSgp-TT4I2SqUTiNqwrehmdjjZdD925Erpdb8ZnrTTcaicmO6G95IvpwfMz3EvJY7A0anjjS_IOJpwoBN3RpgftGQcuFIaOc10xa5DC9TcS1-HouoyR-FdciqEOr3ZaOhr_em3W3MLqr6IMBTALz__rObKrb7kAUPNiBfy5fUhznbp2VgQeJYQRIxGQDOnn-_5bfFjsWjQAz098SknNAwOKtdy9BpRPwyrVybQ17i15DJcAP92aSIMP7dhYvDpuSvHBg5GhHNT3y5abd_o4ZXpWpSwqSpxAHqGE5g
>
< HTTP/1.1 401 Unauthorized
< Content-Type: text/plain; charset=utf-8
< X-Content-Type-Options: nosniff
< Date: Sat, 25 Jan 2020 09:21:16 GMT
< Content-Length: 13
<
{ [13 bytes data]
* Connection #0 to host kube-rbac-proxy.default.svc left intact
Unauthorized
```
