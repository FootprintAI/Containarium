.PHONY: help proto build clean clean-ui clean-all install test lint fmt run-local webui swagger-ui build-mcp build-mcp-linux install-mcp

# Variables
BINARY_NAME=containarium
MCP_BINARY_NAME=mcp-server
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

webui: ## Build Web UI static files for embedding
	@echo "==> Building Web UI..."
	@chmod +x scripts/build-webui.sh
	@./scripts/build-webui.sh

proto-lint: ## Lint protobuf definitions
	@echo "==> Linting protobuf definitions..."
	@buf lint

proto-breaking: ## Check for breaking changes in protobuf definitions
	@echo "==> Checking for breaking changes..."
	@buf breaking --against '.git#branch=main'

build: proto webui swagger-ui ## Build the containarium binary (includes Swagger UI)
	@echo "==> Building containarium..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/containarium/main.go
	@echo "==> Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-fast: proto ## Build the containarium binary (skip Swagger UI download, uses CDN)
	@echo "==> Building containarium (fast mode - CDN fallback)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) cmd/containarium/main.go
	@echo "==> Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux: proto web-ui swagger-ui ## Build for Linux (for deployment to GCE, includes Swagger UI)
	@echo "==> Building containarium for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/containarium/main.go
	@echo "==> Binary built: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

build-all: proto web-ui swagger-ui ## Build for all platforms (includes Swagger UI)
	@echo "==> Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/containarium/main.go
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/containarium/main.go
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/containarium/main.go
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

test-reboot: ## Run reboot persistence test (requires GCP access)
	@echo "==> Running reboot persistence test..."
	@chmod +x scripts/reboot-persistence-test.sh
	@./scripts/reboot-persistence-test.sh full

test-reboot-prepare: ## Prepare reboot test (step 1)
	@chmod +x scripts/reboot-persistence-test.sh
	@./scripts/reboot-persistence-test.sh prepare

test-reboot-verify: ## Verify after reboot (step 3)
	@chmod +x scripts/reboot-persistence-test.sh
	@./scripts/reboot-persistence-test.sh verify

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
