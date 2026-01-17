package buildpack

import (
	"fmt"
	"strings"
)

// NodeJSDetector detects Node.js applications
type NodeJSDetector struct{}

// Name returns the language name
func (d *NodeJSDetector) Name() string {
	return "Node.js"
}

// Detect checks if the project is a Node.js application
func (d *NodeJSDetector) Detect(files []string) (bool, string) {
	if !containsFile(files, "package.json") {
		return false, ""
	}

	// Default version
	version := "20"

	// Try to detect version from package.json engines field
	// In practice, we'd parse package.json here
	// For now, return default version
	return true, version
}

// GenerateDockerfile generates a Dockerfile for Node.js applications
func (d *NodeJSDetector) GenerateDockerfile(opts GenerateOptions) (string, error) {
	nodeVersion := opts.NodeVersion
	if nodeVersion == "" {
		nodeVersion = "20"
	}

	port := opts.Port
	if port == 0 {
		port = 3000
	}

	// Detect start command based on files
	startCommand := d.detectStartCommand(opts.Files)

	// Detect if it's a Next.js app
	isNextJS := d.isNextJS(opts.Files)

	// Check for package-lock.json
	hasLockFile := containsFile(opts.Files, "package-lock.json")

	var dockerfile string
	if isNextJS {
		dockerfile = d.generateNextJSDockerfile(nodeVersion, port)
	} else {
		dockerfile = d.generateStandardDockerfile(nodeVersion, port, startCommand, hasLockFile)
	}

	return dockerfile, nil
}

func (d *NodeJSDetector) detectStartCommand(files []string) string {
	// Priority order for start commands
	if containsFile(files, "server.js") {
		return `["node", "server.js"]`
	}
	if containsFile(files, "index.js") {
		return `["node", "index.js"]`
	}
	if containsFile(files, "app.js") {
		return `["node", "app.js"]`
	}
	if containsFile(files, "main.js") {
		return `["node", "main.js"]`
	}
	// Default to npm start
	return `["npm", "start"]`
}

func (d *NodeJSDetector) isNextJS(files []string) bool {
	for _, f := range files {
		if strings.Contains(f, "next.config") {
			return true
		}
	}
	return false
}

func (d *NodeJSDetector) generateStandardDockerfile(nodeVersion string, port int, startCommand string, hasLockFile bool) string {
	// Use npm ci if package-lock.json exists, otherwise npm install
	installCmd := "npm install --omit=dev"
	if hasLockFile {
		installCmd = "npm ci --omit=dev"
	}

	return fmt.Sprintf(`# Auto-generated Dockerfile for Node.js
FROM node:%s-alpine

WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN %s

# Copy application code
COPY . .

# Expose port
EXPOSE %d

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:%d/', (r) => process.exit(r.statusCode === 200 ? 0 : 1))" || exit 1

# Start application
CMD %s
`, nodeVersion, installCmd, port, port, startCommand)
}

func (d *NodeJSDetector) generateNextJSDockerfile(nodeVersion string, port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for Next.js
FROM node:%s-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM node:%s-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:%s-alpine AS runner
WORKDIR /app
ENV NODE_ENV production

# Copy necessary files
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE %d
ENV PORT %d

CMD ["node", "server.js"]
`, nodeVersion, nodeVersion, nodeVersion, port, port)
}
