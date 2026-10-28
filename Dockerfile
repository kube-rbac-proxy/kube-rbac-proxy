ARG GOARCH=amd64

ARG BASEIMAGE=gcr.io/distroless/static:nonroot-$GOARCH
FROM $BASEIMAGE

ARG GOARCH
ARG GOOS=linux
ARG BINARY=kube-rbac-proxy-$GOOS-$GOARCH
COPY _output/$BINARY /usr/local/bin/kube-rbac-proxy
EXPOSE 8080
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kube-rbac-proxy"]