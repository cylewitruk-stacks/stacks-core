GO ?= go
CONTROLLER_GEN ?= $(GO) run -modfile=tools/go.mod sigs.k8s.io/controller-tools/cmd/controller-gen

.PHONY: fmt generate test test-integration test-race vet verify

fmt:
	@test -z "$$(gofmt -l .)" || { echo "Go sources are not formatted" >&2; exit 1; }

generate:
	$(CONTROLLER_GEN) object paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/v1beta1 output:crd:artifacts:config=../crds

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

test-integration:
	@test -n "$(KUBEBUILDER_ASSETS)" || { echo "KUBEBUILDER_ASSETS is required" >&2; exit 1; }
	$(GO) test -tags=integration ./internal/integration -count=1

verify: fmt generate vet test test-race
	@git diff --exit-code -- api/v1alpha1/zz_generated.deepcopy.go api/v1beta1/zz_generated.deepcopy.go ../crds/testing.stacks.org_*.yaml
