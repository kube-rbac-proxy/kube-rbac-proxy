all: check-license build generate test

GO111MODULE=on
export GO111MODULE

# Set DBG=1 to build without stripping debug symbols. Default produces a
# stripped binary.
DBG ?=

ifeq ($(DBG),1)
DBG_GCFLAGS := all=-N -l
else
STRIP_LDFLAGS := -s -w
endif

PROGRAM_NAME?=kube-rbac-proxy
# This repository moved to github.com/kube-rbac-proxy/kube-rbac-proxy.
# Keep the old module path until the 1.0 release, where this is subject to change.
GITHUB_URL=github.com/brancz/kube-rbac-proxy
GOOS?=$(shell uname -s | tr A-Z a-z)
GOARCH?=$(shell go env GOARCH)
BASEIMAGE?=gcr.io/distroless/static:nonroot-$(GOARCH)
OUT_DIR=_output
VERSION?=$(shell cat VERSION)-$(shell git rev-parse --short HEAD)
VERSION_SEMVER?=$(shell echo $(VERSION) | grep -o 'v[0-9]\+\.[0-9]\+\.[0-9]\+')
PKGS=$(shell go list ./... | grep -v /test/e2e)
DOCKER_REPO?=quay.io/brancz/kube-rbac-proxy
KUBECONFIG?=$(HOME)/.kube/config
CONTAINER_NAME?=$(DOCKER_REPO):$(VERSION)

ALL_ARCH=amd64 arm arm64 ppc64le s390x
ALL_PLATFORMS=$(addprefix linux/,$(ALL_ARCH))
ALL_BINARIES ?= $(addprefix $(OUT_DIR)/$(PROGRAM_NAME)-, \
				$(addprefix linux-,$(ALL_ARCH)) \
				darwin-amd64 \
				windows-amd64.exe)

TOOLS_BIN_DIR?=$(shell pwd)/tmp/bin
export PATH := $(TOOLS_BIN_DIR):$(PATH)

EMBEDMD_BINARY=$(TOOLS_BIN_DIR)/embedmd
TOOLING=$(EMBEDMD_BINARY)

check-license:
	@echo ">> checking license headers"
	@./scripts/check_license.sh

crossbuild: $(ALL_BINARIES)

$(OUT_DIR)/$(PROGRAM_NAME): $(OUT_DIR)/$(PROGRAM_NAME)-$(GOOS)-$(GOARCH)
	cp $(OUT_DIR)/$(PROGRAM_NAME)-$(GOOS)-$(GOARCH) $(OUT_DIR)/$(PROGRAM_NAME)

$(OUT_DIR)/$(PROGRAM_NAME)-%:
	@echo ">> building for $(GOOS)/$(GOARCH) to $(OUT_DIR)/$(PROGRAM_NAME)-$*"
	GOARCH=$(word 2,$(subst -, ,$(*:.exe=))) \
	GOOS=$(word 1,$(subst -, ,$(*:.exe=))) \
	CGO_ENABLED=0 \
	go build --installsuffix cgo -gcflags="$(DBG_GCFLAGS)" -ldflags="$(GOLDFLAGS) $(STRIP_LDFLAGS) -X k8s.io/component-base/version.gitVersion=$(VERSION_SEMVER) -X k8s.io/component-base/version.gitCommit=$(shell git rev-parse HEAD) -X k8s.io/component-base/version/verflag.programName=$(PROGRAM_NAME)" -o $(OUT_DIR)/$(PROGRAM_NAME)-$* $(GITHUB_URL)/cmd/kube-rbac-proxy

clean:
	-rm -r $(OUT_DIR)

build: clean $(OUT_DIR)/$(PROGRAM_NAME)

update-go-deps:
	@for m in $$(go list -mod=readonly -m -f '{{ if and (not .Indirect) (not .Main)}}{{.Path}}{{end}}' all); do \
		go get -u $$m; \
	done
	go mod tidy

container: $(OUT_DIR)/$(PROGRAM_NAME)-$(GOOS)-$(GOARCH) Dockerfile
	docker build --build-arg BINARY=$(PROGRAM_NAME)-$(GOOS)-$(GOARCH) --build-arg GOARCH=$(GOARCH) --build-arg BASEIMAGE=$(BASEIMAGE) -t $(CONTAINER_NAME)-$(GOARCH) .
ifeq ($(GOARCH), amd64)
	docker tag $(DOCKER_REPO):$(VERSION)-$(GOARCH) $(CONTAINER_NAME)
endif

manifest-tool:
	curl -fsSL https://github.com/estesp/manifest-tool/releases/download/v1.0.2/manifest-tool-linux-amd64 > ./manifest-tool
	chmod +x ./manifest-tool

push-%:
	$(MAKE) GOARCH=$* container
	docker push $(DOCKER_REPO):$(VERSION)-$*

comma:= ,
empty:=
space:= $(empty) $(empty)
manifest-push: manifest-tool
	./manifest-tool push from-args --platforms $(subst $(space),$(comma),$(ALL_PLATFORMS)) --template $(DOCKER_REPO):$(VERSION)-ARCH --target $(DOCKER_REPO):$(VERSION)

push: crossbuild manifest-tool $(addprefix push-,$(ALL_ARCH)) manifest-push

test-container: $(OUT_DIR)/$(PROGRAM_NAME)-linux-$(GOARCH) Dockerfile
	docker build --build-arg BINARY=$(PROGRAM_NAME)-linux-$(GOARCH) --build-arg BASEIMAGE=$(BASEIMAGE) -t $(CONTAINER_NAME) .

curl-container:
	docker build -f ./examples/example-client/Dockerfile -t quay.io/brancz/krp-curl:v0.0.2 .

curl-container-multi:
	docker buildx build --platform linux/amd64,linux/arm64 -f ./examples/example-client/Dockerfile -t quay.io/brancz/krp-curl:v0.0.2 .

run-curl-container:
	@echo 'Example: curl -v -s -k -H "Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`" https://kube-rbac-proxy.default.svc:8443/metrics'
	kubectl run -i -t krp-curl --image=quay.io/brancz/krp-curl:v0.0.2 --restart=Never --command -- /bin/sh

grpcc-container:
	docker build -f ./examples/grpcc/Dockerfile -t mumoshu/grpcc:v0.0.1 .

test-container: $(OUT_DIR)/$(PROGRAM_NAME)-linux-$(GOARCH) Dockerfile
	docker build --build-arg BINARY=$(PROGRAM_NAME)-linux-$(GOARCH) --build-arg BASEIMAGE=$(BASEIMAGE) -t $(CONTAINER_NAME) .

test: test-unit test-e2e

test-unit:
	go test -v -race -count=1 $(PKGS)

test-e2e:
	go test -timeout 55m -v ./test/e2e/ $(TEST_RUN_ARGS)

test-local-setup: VERSION = local
test-local-setup: VERSION_SEMVER = $(shell cat VERSION)
test-local-setup: clean test-container kind-create-cluster
test-local: test-local-setup test

kind-delete-cluster:
	kind delete cluster

kind-create-cluster: curl-container kind-delete-cluster
	kind create cluster --config ./test/e2e/kind-config/kind-config.yaml
	kind load docker-image $(CONTAINER_NAME) quay.io/brancz/krp-curl:v0.0.2

generate: build $(EMBEDMD_BINARY)
	@echo ">> generating examples"
	@./scripts/generate-examples.sh
	@echo ">> generating docs"
	@./scripts/generate-help-txt.sh
	@$(EMBEDMD_BINARY) -w `find ./ -name "*.md" -print`

$(TOOLS_BIN_DIR):
	@mkdir -p $(TOOLS_BIN_DIR)

$(TOOLING): $(TOOLS_BIN_DIR)
	@echo Installing tools from scripts/tools.go
	@cat scripts/tools.go | grep _ | awk -F'"' '{print $$2}' | GOBIN=$(TOOLS_BIN_DIR) xargs -tI % go install -mod=readonly -modfile=scripts/go.mod %

.PHONY: all check-license crossbuild build container push push-% manifest-push test-container curl-container test test-unit test-e2e generate update-go-deps clean kind-delete-cluster kind-create-cluster
