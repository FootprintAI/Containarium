package buildpack

import (
	"fmt"
)

// RustDetector detects Rust applications
type RustDetector struct{}

// Name returns the language name
func (d *RustDetector) Name() string {
	return "Rust"
}

// Detect checks if the project is a Rust application
func (d *RustDetector) Detect(files []string) (bool, string) {
	if !containsFile(files, "Cargo.toml") {
		return false, ""
	}

	// Default version
	return true, "1.75"
}

// GenerateDockerfile generates a Dockerfile for Rust applications
func (d *RustDetector) GenerateDockerfile(opts GenerateOptions) (string, error) {
	rustVersion := opts.RustVersion
	if rustVersion == "" {
		rustVersion = "1.75"
	}

	port := opts.Port
	if port == 0 {
		port = 8080
	}

	return fmt.Sprintf(`# Auto-generated Dockerfile for Rust
# Build stage
FROM rust:%s AS builder

WORKDIR /app

# Create a new empty shell project
RUN USER=root cargo new --bin app
WORKDIR /app/app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Build dependencies (for caching)
RUN cargo build --release
RUN rm src/*.rs

# Copy source code
COPY src ./src

# Build the actual application
RUN rm ./target/release/deps/app*
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install SSL certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /app/app/target/release/app ./app

# Expose port
EXPOSE %d

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:%d/health || exit 1

# Run
CMD ["./app"]
`, rustVersion, port, port), nil
}
