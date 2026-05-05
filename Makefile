GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)
BUILD_DIR = dist/${GOOS}_${GOARCH}

ifeq ($(GOOS),windows)
OUTPUT_PATH = ${BUILD_DIR}/baton-hashicorp-vault.exe
else
OUTPUT_PATH = ${BUILD_DIR}/baton-hashicorp-vault
endif

.PHONY: build
build:
	go build -o ${OUTPUT_PATH} ./cmd/baton-hashicorp-vault

.PHONY: update-deps
update-deps:
	go get -d -u ./...
	go mod tidy -v
	go mod vendor

.PHONY: add-dep
add-dep:
	go mod tidy -v
	go mod vendor

GOLANGCI_LINT_VERSION = v2.11.4

.PHONY: lint
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run
