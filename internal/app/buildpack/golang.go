package buildpack

import (
	"fmt"
)

// GoDetector detects Go applications
type GoDetector struct{}

// Name returns the language name
func (d *GoDetector) Name() string {
	return "Go"
}

// Detect checks if the project is a Go application
func (d *GoDetector) Detect(files []string) (bool, string) {
	if !containsFile(files, "go.mod") {
		return false, ""
	}

	// Default version - would normally parse go.mod
	return true, "1.22"
}

// GenerateDockerfile generates a Dockerfile for Go applications
func (d *GoDetector) GenerateDockerfile(opts GenerateOptions) (string, error) {
	goVersion := opts.GoVersion
	if goVersion == "" {
		goVersion = "1.22"
	}

	port := opts.Port
	if port == 0 {
		port = 8080
	}

	// Detect main package location
	mainPackage := d.detectMainPackage(opts.Files)

	return fmt.Sprintf(`# Auto-generated Dockerfile for Go
# Build stage
FROM golang:%s-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files first for better caching
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /app/server %s

# Runtime stage
FROM scratch

# Copy certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy binary
COPY --from=builder /app/server /server

# Expose port
EXPOSE %d

# Health check - using wget since scratch image has no shell
# Note: For scratch images, health checks often need to be handled by orchestrator

# Run
ENTRYPOINT ["/server"]
`, goVersion, mainPackage, port), nil
}

func (d *GoDetector) detectMainPackage(files []string) string {
	// Check for common main package locations
	for _, f := range files {
		switch f {
		case "main.go":
			return "."
		case "cmd/server/main.go":
			return "./cmd/server"
		case "cmd/app/main.go":
			return "./cmd/app"
		case "cmd/main.go":
			return "./cmd"
		}
	}

	// Check if there's any cmd/* directory
	for _, f := range files {
		if len(f) > 4 && f[:4] == "cmd/" {
			return "./cmd/..."
		}
	}

	// Default to current directory
	return "."
}
