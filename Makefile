.PHONY: help proto build build-bpf clean clean-ui clean-all install test lint fmt run-local web-ui swagger-ui build-mcp build-mcp-linux install-mcp build-agent-box build-agent-box-linux build-agent-box-all install-agent-box build-agent-runtime bundle-agent-runtime build-release sidecar-build-otel bundle-download-deps build-bundle build-bundle-all

# Variables
BINARY_NAME=containarium
MCP_BINARY_NAME=mcp-server
AGENTBOX_BINARY_NAME=agent-box
GIT_COMMIT?=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_DIR=bin
PROTO_DIR=proto
PKG_DIR=pkg/pb

# Go build flags
# Note: Version is statically defined in pkg/version/version.go (manually updated)
# You can override at build time with: make build VERSION=1.2.3
LDFLAGS=-ldflags "-X github.com/footprintai/containarium/pkg/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/footprintai/containarium/pkg/version.BuildTime=$(BUILD_TIME)"

# Allow optional version override
ifdef VERSION
	LDFLAGS=-ldflags "-X github.com/footprintai/containarium/pkg/version.Version=$(VERSION) \
		-X github.com/footprintai/containarium/pkg/version.GitCommit=$(GIT_COMMIT) \
		-X github.com/footprintai/containarium/pkg/version.BuildTime=$(BUILD_TIME)"
endif

GOFLAGS=-v

# eBPF network-policy object (#627 follow-up). `make build-bpf` compiles it into
# BPF_OBJ; it is gitignored — built in CI / on a backend, never committed. When
# the object is present, GO_TAGS auto-enables the `embed_bpf` build tag so the
# containarium binary bakes it in (internal/netbpf/embed_bpf.go). A normal dev
# build (no object, no clang) leaves GO_TAGS empty and uses the stub. Because
# $(wildcard) is evaluated at parse time, CI runs `make build-bpf` as a separate
# invocation before `make build-release`.
BPF_SRC := experimental/ebpf-phaseA/netpolicy.bpf.c
BPF_OBJ := internal/netbpf/netpolicy.bpf.o
GO_TAGS :=
ifneq ($(wildcard $(BPF_OBJ)),)
	GO_TAGS := -tags embed_bpf
endif

# Default target
help: ## Show this help message
	@echo "Containarium - SSH Jump Server + LXC Container Platform"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

proto: ## Generate Go code from protobuf definitions
	@echo "==> Generating protobuf code..."
	@if command -v buf > /dev/null; then \
		buf generate; \
	else \
		echo "Error: buf is not installed. Install with: brew install bufbuild/buf/buf"; \
		exit 1; \
	fi
	@echo "==> Protobuf code generated successfully"

swagger-ui: ## Download and install Swagger UI static files
	@echo "==> Downloading Swagger UI..."
	@chmod +x scripts/download-swagger-ui.sh
	@./scripts/download-swagger-ui.sh

web-ui: ## Build Web UI static files for embedding
	@echo "==> Building Web UI..."
	@chmod +x scripts/build-webui.sh
	@./scripts/build-webui.sh

proto-lint: ## Lint protobuf definitions
	@echo "==> Linting protobuf definitions..."
	@buf lint

proto-breaking: ## Check for breaking changes in protobuf definitions
	@echo "==> Checking for breaking changes..."
	@buf breaking --against '.git#branch=main'

build-bpf: ## Compile the eBPF network-policy object for embedding (Linux; needs clang + kernel UAPI headers)
	@echo "==> Compiling eBPF object $(BPF_OBJ)..."
	@clang -O2 -g -target bpfel \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "==> eBPF object built: $(BPF_OBJ) ($$(wc -c < $(BPF_OBJ)) bytes). Re-run make to pick up -tags embed_bpf."

build: proto web-ui swagger-ui ## Build the containarium binary (includes Swagger UI)
	@echo "==> Building containarium..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GOFLAGS) $(GO_TAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/containarium/main.go
	@echo "==> Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-fast: proto ## Build the containarium binary (skip Swagger UI download, uses CDN)
	@echo "==> Building containarium (fast mode - CDN fallback)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GOFLAGS) $(GO_TAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/containarium/main.go
	@echo "==> Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux: proto web-ui swagger-ui ## Build for Linux (for deployment to GCE, includes Swagger UI)
	@echo "==> Building containarium for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(GO_TAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/containarium/main.go
	@echo "==> Binary built: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

build-all: proto web-ui swagger-ui ## Build for all platforms (includes Swagger UI)
	@echo "==> Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(GO_TAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/containarium/main.go
	@GOOS=darwin GOARCH=amd64 go build $(GO_TAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/containarium/main.go
	@GOOS=darwin GOARCH=arm64 go build $(GO_TAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/containarium/main.go
	# Windows is CLIENT-ONLY: the daemon/sentinel/tunnel + direct-DB admin
	# subcommands are //go:build !windows, so this binary exposes only the
	# remote-client commands (create/list/ssh/…). The daemon stays linux/mac.
	@GOOS=windows GOARCH=amd64 go build $(GO_TAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/containarium/main.go
	@echo "==> Binaries built in $(BUILD_DIR)/"

build-mcp: ## Build the MCP server binary
	@echo "==> Building MCP server..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(MCP_BINARY_NAME) cmd/mcp-server/main.go
	@echo "==> MCP server built: $(BUILD_DIR)/$(MCP_BINARY_NAME)"

build-mcp-linux: ## Build MCP server for Linux (for deployment)
	@echo "==> Building MCP server for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(MCP_BINARY_NAME)-linux-amd64 cmd/mcp-server/main.go
	@echo "==> MCP server built: $(BUILD_DIR)/$(MCP_BINARY_NAME)-linux-amd64"

build-mcp-all: ## Build MCP server for all platforms
	@echo "==> Building MCP server for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(MCP_BINARY_NAME)-linux-amd64 cmd/mcp-server/main.go
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(MCP_BINARY_NAME)-darwin-amd64 cmd/mcp-server/main.go
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(MCP_BINARY_NAME)-darwin-arm64 cmd/mcp-server/main.go
	@echo "==> MCP server binaries built in $(BUILD_DIR)/"

install-mcp: build-mcp ## Install the MCP server binary to /usr/local/bin (requires sudo)
	@echo "==> Installing $(MCP_BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(MCP_BINARY_NAME) /usr/local/bin/
	@echo "==> Installed successfully. Configure in Claude Desktop to use it"

build-agent-box: ## Build the in-the-box agent-box MCP binary
	@echo "==> Building agent-box..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME) cmd/agent-box/main.go
	@echo "==> agent-box built: $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME)"

build-agent-runtime: ## Build the in-box agent-runtime loop (Node/TS sibling package; its own lane, not a Go binary)
	@echo "==> Building agent-runtime (npm ci + tsc)..."
	@cd agent-runtime && npm ci && npm run build
	@echo "==> agent-runtime built: agent-runtime/dist/"

bundle-agent-runtime: build-agent-runtime ## Package agent-runtime as a release tarball (dist + manifests; `npm ci --omit=dev` runs in-box)
	@echo "==> Packaging agent-runtime bundle..."
	@mkdir -p $(BUILD_DIR)
	@tar -czf $(BUILD_DIR)/agent-runtime-bundle.tar.gz -C agent-runtime dist package.json package-lock.json
	@echo "==> agent-runtime bundle: $(BUILD_DIR)/agent-runtime-bundle.tar.gz (publish alongside agent-box-linux-amd64; scripts/install-agent-runtime.sh consumes both)"

build-agent-box-linux: ## Build agent-box for Linux (the typical install target — agent-box runs INSIDE LXC containers)
	@echo "==> Building agent-box for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME)-linux-amd64 cmd/agent-box/main.go
	@echo "==> agent-box built: $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME)-linux-amd64"

build-agent-box-all: ## Build agent-box for all platforms
	@echo "==> Building agent-box for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME)-linux-amd64 cmd/agent-box/main.go
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME)-darwin-amd64 cmd/agent-box/main.go
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME)-darwin-arm64 cmd/agent-box/main.go
	@echo "==> agent-box binaries built in $(BUILD_DIR)/"

install-agent-box: build-agent-box ## Install agent-box to /usr/local/bin (requires sudo)
	@echo "==> Installing $(AGENTBOX_BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(AGENTBOX_BINARY_NAME) /usr/local/bin/
	@echo "==> Installed. Wire it into Claude Code/Cursor with: ssh user@box agent-box"

# Sidecar image build. Per docs/PLATFORM-SIDECAR-DESIGN.md, sidecar
# images live at ghcr.io/footprintai/containarium-*-sidecar; on
# FootprintAI's GitHub org public-package visibility is admin-locked,
# so for now operators build the image themselves from the bundled
# source. The tag tracks pkg/version.Version (decision P4).
sidecar-build-otel: ## Build the otel-sidecar Docker image locally (tag = pkg/version)
	$(eval SIDECAR_VERSION := $(shell grep '^[[:space:]]*Version = ' pkg/version/version.go | head -1 | sed -E 's/.*"([^"]+)".*/\1/'))
	@echo "==> Building containarium-otel-sidecar:v$(SIDECAR_VERSION) from sidecars/otel-sidecar/..."
	@docker build \
		--tag containarium-otel-sidecar:v$(SIDECAR_VERSION) \
		--tag containarium-otel-sidecar:latest \
		sidecars/otel-sidecar/
	@echo "==> Built. The compose snippet from \`containarium sidecar otel compose <user>\` references this tag."

# build-release produces every release artifact for every supported
# platform: containarium + mcp-server + agent-box, each for
# linux/amd64, darwin/amd64, darwin/arm64. Used by the release.yml
# workflow on v* tag pushes; safe to run locally to dry-run a release.
build-release: build-all build-mcp-all build-agent-box-all ## Build all 10 release artifacts (CLI ×4 platforms incl. windows; mcp/agent-box ×3) + checksums
	@echo "==> Generating SHA256SUMS..."
	@cd $(BUILD_DIR) && \
	  shasum -a 256 \
	    $(BINARY_NAME)-linux-amd64 \
	    $(BINARY_NAME)-darwin-amd64 \
	    $(BINARY_NAME)-darwin-arm64 \
	    $(BINARY_NAME)-windows-amd64.exe \
	    $(MCP_BINARY_NAME)-linux-amd64 \
	    $(MCP_BINARY_NAME)-darwin-amd64 \
	    $(MCP_BINARY_NAME)-darwin-arm64 \
	    $(AGENTBOX_BINARY_NAME)-linux-amd64 \
	    $(AGENTBOX_BINARY_NAME)-darwin-amd64 \
	    $(AGENTBOX_BINARY_NAME)-darwin-arm64 \
	    > SHA256SUMS.txt
	@echo "==> Release artifacts ready in $(BUILD_DIR)/:"
	@ls -1 $(BUILD_DIR)/

# ---- Air-gapped install bundle (E3a/E3b) ----
# Per prd/cloud/air-gapped-install-bundle.md, ship a `.tar.gz` bundle
# that bakes in every binary, toolchain, .deb, and sidecar image needed
# to install Containarium on a host with zero internet egress. The
# bundle wraps `make build-release` output + a download-cache populated
# by scripts/bundle/download-deps.sh.
BUNDLE_OS?=linux
BUNDLE_ARCH?=amd64
BUNDLE_VERSION?=$(shell grep '^[[:space:]]*Version = ' pkg/version/version.go | head -1 | sed -E 's/.*"([^"]+)".*/v\1/')

bundle-download-deps: ## Pull toolchains + apt packages into dist/bundle-cache/ (run once per OS/ARCH)
	@echo "==> Downloading bundle dependencies for $(BUNDLE_OS)/$(BUNDLE_ARCH)..."
	@chmod +x scripts/bundle/download-deps.sh
	@OS=$(BUNDLE_OS) ARCH=$(BUNDLE_ARCH) ./scripts/bundle/download-deps.sh

build-bundle: build-release ## Assemble the air-gapped install bundle tarball
	@echo "==> Building air-gapped bundle $(BUNDLE_VERSION) for $(BUNDLE_OS)/$(BUNDLE_ARCH)..."
	@chmod +x scripts/bundle/build-bundle.sh
	@VERSION=$(BUNDLE_VERSION) OS=$(BUNDLE_OS) ARCH=$(BUNDLE_ARCH) \
		./scripts/bundle/build-bundle.sh

build-bundle-all: ## Build bundles for linux/amd64 and linux/arm64
	@$(MAKE) build-bundle BUNDLE_OS=linux BUNDLE_ARCH=amd64
	@$(MAKE) build-bundle BUNDLE_OS=linux BUNDLE_ARCH=arm64

install: build ## Install the binary to /usr/local/bin (requires sudo)
	@echo "==> Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "==> Installed successfully. Run '$(BINARY_NAME) --help' to get started"

clean: ## Clean build artifacts
	@echo "==> Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(PKG_DIR)
	@echo "==> Clean complete"

clean-ui: ## Clean embedded UI files (swagger-ui and webui)
	@echo "==> Cleaning UI files..."
	@rm -rf internal/gateway/swagger-ui/*
	@rm -rf internal/gateway/webui/*
	@touch internal/gateway/swagger-ui/.gitkeep
	@touch internal/gateway/webui/.gitkeep
	@echo "==> UI files cleaned (swagger-ui and webui)"

clean-all: clean clean-ui ## Clean all artifacts including UI files
	@echo "==> All artifacts cleaned"

test: ## Run unit tests
	@echo "==> Running unit tests..."
	@go test -v -race -coverprofile=coverage.out ./...

test-mcp: ## Run MCP server tests
	@echo "==> Running MCP server tests..."
	@go test -v -race -coverprofile=mcp-coverage.out ./internal/mcp

test-mcp-verbose: ## Run MCP tests with verbose output
	@echo "==> Running MCP tests (verbose)..."
	@go test -v -count=1 ./internal/mcp

test-mcp-coverage: ## Run MCP tests and show coverage
	@echo "==> Running MCP tests with coverage..."
	@go test -v -coverprofile=mcp-coverage.out ./internal/mcp
	@go tool cover -html=mcp-coverage.out -o mcp-coverage.html
	@echo "==> Coverage report: mcp-coverage.html"

test-short: ## Run tests in short mode (skip integration tests)
	@echo "==> Running unit tests (short mode)..."
	@go test -v -short -race ./...

test-integration: ## Run integration tests (requires running instance)
	@echo "==> Running integration tests..."
	@if [ -z "$$CONTAINARIUM_SERVER" ]; then \
		echo "Warning: CONTAINARIUM_SERVER not set, using localhost:50051"; \
		echo "Set CONTAINARIUM_SERVER environment variable to test against remote server"; \
	fi
	@cd test/integration && go test -v -timeout 15m

test-e2e: ## Run end-to-end reboot persistence test using Terraform (RECOMMENDED)
	@echo "==> Running E2E reboot persistence test with Terraform..."
	@if [ -z "$$GCP_PROJECT" ]; then \
		echo "Error: GCP_PROJECT environment variable not set"; \
		echo "Set it to your GCP project ID: export GCP_PROJECT=your-project-id"; \
		exit 1; \
	fi
	@cd test/integration && go test -v -run TestE2ERebootPersistenceTerraform -timeout 45m

test-e2e-gcloud: ## Run end-to-end test using gcloud (alternative method)
	@echo "==> Running E2E reboot persistence test with gcloud..."
	@if [ -z "$$GCP_PROJECT" ]; then \
		echo "Error: GCP_PROJECT environment variable not set"; \
		echo "Set it to your GCP project ID: export GCP_PROJECT=your-project-id"; \
		exit 1; \
	fi
	@cd test/integration && go test -v -run TestE2ERebootPersistence -timeout 45m

test-all: test-short test-integration ## Run all tests

test-coverage: test ## Run tests and show coverage report
	@echo "==> Generating coverage report..."
	@go tool cover -html=coverage.out

lint: ## Run linters
	@echo "==> Running linters..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install with: brew install golangci-lint"; \
		go vet ./...; \
	fi

fmt: ## Format Go code
	@echo "==> Formatting Go code..."
	@go fmt ./...
	@gofmt -s -w .

tidy: ## Tidy Go modules
	@echo "==> Tidying Go modules..."
	@go mod tidy

deps: ## Download Go dependencies
	@echo "==> Downloading dependencies..."
	@go mod download

run-local: build ## Run containarium locally (for testing)
	@echo "==> Running containarium..."
	@$(BUILD_DIR)/$(BINARY_NAME)

terraform-init: ## Initialize Terraform
	@echo "==> Initializing Terraform..."
	@cd terraform/gce && terraform init

terraform-plan: ## Run Terraform plan
	@echo "==> Running Terraform plan..."
	@cd terraform/gce && terraform plan

terraform-apply: ## Apply Terraform configuration
	@echo "==> Applying Terraform configuration..."
	@cd terraform/gce && terraform apply

terraform-destroy: ## Destroy Terraform resources
	@echo "==> Destroying Terraform resources..."
	@cd terraform/gce && terraform destroy

setup-dev: deps proto ## Set up development environment
	@echo "==> Setting up development environment..."
	@echo "==> Installing pre-commit hooks..."
	@echo "#!/bin/sh\nmake fmt lint test" > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "==> Development environment ready!"

version: ## Show version information
	@echo "Containarium version: $(VERSION)"
	@echo "Go version: $(shell go version)"
	@echo "Build platform: $(shell go env GOOS)/$(shell go env GOARCH)"

.DEFAULT_GOAL := help
