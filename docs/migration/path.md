# Allow Path and Ignore Path

## Description

If `--allow-paths` is set, only the requests to these paths will be considered for proxying, the rest will be rejected.
If `--ignore-paths` is set, requests to these paths will be passed upstream without any authorization.

Only one of `--allow-paths`/`--ignore-paths` is allowed to be set at a time.

## Change

Previously, it was possible to configure an **infix wildcard** but that will now fail.
Now **infix regex** will cause an error on server startup.
kube-rbac-proxy won't start with an **infix regex**.
E.g. `--allow-path="/api/v1/*/values"` will cause kube-rbac-proxy fail to start.
E.g. `--ignore-path="/api/v1/*/values"` will cause kube-rbac-proxy fail to start.

Previously `*` would count as a single-path-segment wildcard ([path.Match](https://pkg.go.dev/path#Match)).
Now the wildcard is matching any string, even if it contains `/`.
E.g. `--allow-path="/api/v1/*"` would have rejected `/api/v1/label/values`, with the change it is being evaluated.
E.g. `--ignore-path="/api/v1/*"` would have evaluated `/api/v1/label/values`, with the change it is being passed through. 

### Reason

We are in an effort to mirate kube-rbac-proxy to the k8s sig-auth organization.
In order to meet the requirements of the k8s sig-auth organization we need to adjust the code base.
The kubernetes code base doesn't allow **infix regex**.
It is considered a security risk in case of misconfiguration.

## Call to action

You need to act if you:

### Use infix wildcard operator

If `/api/v1/*/values` was used and `/api/v1/labels` shouldn't match `/api/v1/*`, it needs to be replaced with every individual path segment.

### Expect wildcard operator to match exactly one path sagment

If `/api/v1/*` shouldn't match `/api/v1/label/values` but `/api/v1/label` it is necessary to replace the wildcard operator with every individual path sagment.

### Use other wildcard operators than `*`, like `?`

If `/api/v1/label*` shouldn't match `/api/v1/labels/values` but `/api/v1/labels` it is necessary to replace the wildcard operator with every individual path sagment.
