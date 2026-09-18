# kube-rbac-proxy

[![Docker Repository on Quay](https://quay.io/repository/brancz/kube-rbac-proxy/status "Docker Repository on Quay")](https://quay.io/repository/brancz/kube-rbac-proxy)

> NOTE: This project is *alpha* stage. Flags, configuration, behavior and design may change significantly in following releases.

The kube-rbac-proxy is a small HTTP proxy for a single upstream, that can perform RBAC authorization against the Kubernetes API using [SubjectAccessReview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/).

In Kubernetes clusters without NetworkPolicies any Pod can perform requests to every other Pod in the cluster. This proxy was developed in order to restrict requests to only those Pods, that present a valid and RBAC authorized token or client TLS certificate.

## Current Future and Deprecation of Flags / Features

The project is seeking to be accepted as a k8s project and therefore we need to align tighter with k8s.
As a result, we use more of the k8s code and need to deprecate features, while introducing others.

The reasons for deprecation are that k8s doesn't support them anymore and partially because it is not a best practice.
An example of "not a best practice" is to offer insecure listening and an example of upstream deprecations are some of the logging flags.

The project states above that it is alpha and "flags, configuration, and behavior" can change significantly.
Nevertheless, the project was treated like a production-v1 project: no breaking changes were introduced.

We will introduce a feature branch called sig-auth-acceptance that shows how kube-rbac-proxy will change.

### Maintenance

We try to keep the current release secure by making necessary updates when necessary, but this is best effort.

An update of Kubernetes from v0.25.2 to v0.25.5 was rolled back as it removed the `--logtostderr` flag.

## Usage

The kube-rbac-proxy has all [`glog`](https://github.com/golang/glog) flags for logging purposes. To use the kube-rbac-proxy there are a few flags you may want to set:

* `--upstream`: This is the upstream you want to proxy to.
* `--config-file`: This file specifies details on the SubjectAccessReview you want to be performed on a request. For example, this could contain that an entity performing a request has to be allowed to perform a `get` on the Deployment called `my-frontend-app`, as well as the ability to configure whether SubjectAccessReviews are rewritten based on requests.

See the [`examples/`](examples/) directory for the following examples:

* [non-resource-url example](examples/non-resource-url)
* [resource-attributes example](examples/resource-attributes)
* [oidc example](examples/oidc)
* [rewriting SubjectAccessReviews based on request query parameters](examples/rewrites)

All command line flags:

[embedmd]:# (_output/help.txt)
```txt
$ kube-rbac-proxy -h
The kube-rbac-proxy is a small HTTP proxy for a single upstream
that can perform RBAC authorization against the Kubernetes API using SubjectAccessReview.

Usage:
  kube-rbac-proxy [flags]

Kube-rbac-proxy flags:

      --allow-paths strings                         Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the request doesn't match, kube-rbac-proxy responds with a 404 status code. If omitted, the incoming request path isn't checked. Cannot be used with --ignore-paths.
      --auth-header-fields-enabled                  When set to true, kube-rbac-proxy adds auth-related fields to the headers of http requests sent to the upstream
      --auth-header-groups-field-name string        The name of the field inside a http(2) request header to tell the upstream server about the user's groups (default "x-remote-groups")
      --auth-header-groups-field-separator string   The separator string used for concatenating multiple group names in a groups header field's value (default "|")
      --auth-header-user-field-name string          The name of the field inside a http(2) request header to tell the upstream server about the user's name (default "x-remote-user")
      --auth-token-audiences strings                Comma-separated list of token audiences to accept. By default a token does not have to have any specific audience. It is recommended to set a specific audience.
      --client-ca-file string                       If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.
      --config-file string                          Configuration file to configure kube-rbac-proxy.
      --http2-disable                               Disable HTTP/2 support
      --http2-max-concurrent-streams uint32         The maximum number of concurrent streams per HTTP/2 connection. (default 100)
      --http2-max-size uint32                       The maximum number of bytes that the server will accept for frame size and buffer per stream in a HTTP/2 request. (default 262144)
      --ignore-paths strings                        Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the requst matches, it will proxy the request without performing an authentication or authorization check. Cannot be used with --allow-paths.
      --insecure-listen-address string              [DEPRECATED] The address the kube-rbac-proxy HTTP server should listen on.
      --kube-api-burst int                          kube-api burst value; needed when kube-api-qps is set
      --kube-api-qps float32                        queries per second to the api, kube-client starts client-side throttling, when breached
      --kubeconfig string                           Path to a kubeconfig file, specifying how to connect to the API server. If unset, in-cluster configuration will be used
      --oidc-ca-file string                         If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.
      --oidc-clientID string                        The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.
      --oidc-groups-claim string                    Identifier of groups in JWT claim, by default set to 'groups' (default "groups")
      --oidc-groups-prefix string                   If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.
      --oidc-issuer string                          The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).
      --oidc-sign-alg stringArray                   Supported signing algorithms, default RS256 (default [RS256])
      --oidc-username-claim string                  Identifier of the user in JWT claim, by default set to 'email' (default "email")
      --oidc-username-prefix string                 If provided, the username will be prefixed with this value to prevent conflicts with other authentication strategies.
      --proxy-endpoints-port int                    The port to securely serve proxy-specific endpoints (such as '/healthz'). Uses the host from the '--secure-listen-address'.
      --secure-listen-address string                The address the kube-rbac-proxy HTTPs server should listen on.
      --tls-cert-file string                        File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert)
      --tls-cipher-suites strings                   Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used
      --tls-curve-preferences int32Slice            Comma-separated list of numeric Go crypto/tls CurveID values, as the allowed key exchange mechanisms for the server. The supported values depend on the Go version used. See https://pkg.go.dev/crypto/tls#CurveID for values supported for each Go version. The order of the list is ignored, and key exchange mechanisms are chosen by Go from this list using an internal preference order. If omitted, the default Go curves will be used. (default [])
      --tls-min-version string                      Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants. (default "VersionTLS12")
      --tls-private-key-file string                 File containing the default x509 private key matching --tls-cert-file.
      --tls-reload-interval duration                [DEPRECATED] The interval at which to watch for TLS certificate changes, by default set to 1 minute. (default 1m0s)
      --upstream string                             The upstream URL to proxy to once requests have successfully been authenticated and authorized.
      --upstream-ca-file string                     The CA the upstream uses for TLS connection. This is required when the upstream uses TLS and its own CA certificate
      --upstream-client-cert-file string            If set, the client will be used to authenticate the proxy to upstream. Requires --upstream-client-key-file to be set, too.
      --upstream-client-key-file string             The key matching the certificate from --upstream-client-cert-file. If set, requires --upstream-client-cert-file to be set, too.
      --upstream-force-h2c                          Force h2c to communiate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only

Global flags:

  -h, --help                     help for kube-rbac-proxy
      --version version[=true]   --version, --version=raw prints version information and quits; --version=vX.Y.Z... sets the reported version
```


### How to update Go dependencies

To update the Go dependencies run `make update-go-deps`.

This might be useful to do during a release.

## Why?

You may ask yourself, why not just use the Kubernetes apiserver proxy functionality? There are two reasons why this makes sense, the first is to take load off of the Kubernetes API, so it can be used for actual requests serving the cluster components, rather than in order to serve client requests. The second and more important reason is, this proxy is intended to be a sidecar that accepts incoming HTTP requests. This way, one can ensure that a request is truly authorized, instead of being able to access an application simply because an entity has network access to it.

## Motivation

I developed this proxy in order to be able to protect [Prometheus](https://prometheus.io/) metrics endpoints. In a scenario, where an attacker might obtain full control over a Pod, that attacker would have the ability to discover a lot of information about the workload as well as the current load of the respective workload. This information could originate for example from the [node-exporter](https://github.com/prometheus/node_exporter) and [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics). Both of those metric sources can commonly be found in Prometheus monitoring stacks on [Kubernetes](https://kubernetes.io/).

This project was created to specifically solve the above problem, however, I felt there is a larger need for such a proxy in general.

## How does it work?

On an incoming request, kube-rbac-proxy first figures out which user is performing the request. The kube-rbac-proxy supports using client TLS certificates, as well as tokens. In case of a client certificates, the certificate is simply validated against the configured CA. In case of a bearer token being presented, the `authentication.k8s.io` is used to perform a `TokenReview`.

Once a user has been authenticated, again the `authentication.k8s.io` is used to perform a `SubjectAccessReview`, in order to authorize the respective request, to ensure the authenticated user has the required RBAC roles.

## Notes on ServiceAccount token security

Note that when using tokens for authentication, the receiving side can use the token to impersonate the client. Only use token authentication, when the receiving side is already higher privileged or the token itself is super low privileged, such as when the only roles bound to it are for authorization purposes with this project. Passing around highly privileged tokens is a security risk, and is not recommended.

This project was built to be used to protect metrics of cluster components. These cluster components are much higher privileged than the Prometheus Pod, so if those Pods were to use the token provided by Prometheus it would actually be lower privileged. It is not recommended to use this method for non infrastructure components.

For better security properties use mTLS for authentication instead, and for user authentication, other methods have yet to be added.

## Why are NetworkPolicies not enough?

There are a couple of reasons why the existence of NetworkPolicies may not cover the same use case(s):

* NetworkPolicies are not available in all providers, installers and distros.
* NetworkPolicies do not apply to Pods with HostNetworking enabled, the use case I created this project with the Prometheus node-exporter requires this.
* Once TLS/OIDC is supported, the kube-rbac-proxy can be used to perform AuthN/AuthZ on users.

## Differentiation to [Envoy](https://www.envoyproxy.io/)/[Istio](https://istio.io/)

This projects is not intended to compete with Envoy or IstioMesh. Although on the surface they seem similar, the goals and usage complement each other. It's perfectly ok to use Envoy as the ingress point of traffic of a Pod, which then forwards traffic to the kube-rbac-proxy, which in turn then proxies to the actually serving application.

Additionally, to my knowledge Envoy neither has nor plans Kubernetes specific RBAC/AuthZ support (maybe it shouldn’t even). My knowledge may very well be incomplete, please point out if it is. After all I'm happy if I don't have to maintain more code, but as long as this serves a purpose to me and no other project can provide it, I'll maintain this.

## Testing

To run tests locally, you need to have [kind](https://kind.sigs.k8s.io/) installed.
By default it uses the default cluster, so be aware that **it overrides your default kind cluster**.

The command to execute the tests is: `make test-local`.

## Roadmap

PRs are more than welcome!

* Tests
