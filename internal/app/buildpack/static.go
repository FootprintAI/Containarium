package buildpack

import (
	"fmt"
)

// StaticDetector detects static HTML/CSS/JS applications
type StaticDetector struct{}

// Name returns the language name
func (d *StaticDetector) Name() string {
	return "Static"
}

// Detect checks if the project is a static web application
func (d *StaticDetector) Detect(files []string) (bool, string) {
	// Check for index.html
	if containsFile(files, "index.html") {
		return true, ""
	}

	// Check for common static site generator outputs
	if containsFile(files, "public/index.html") || containsFile(files, "dist/index.html") {
		return true, ""
	}

	return false, ""
}

// GenerateDockerfile generates a Dockerfile for static web applications
func (d *StaticDetector) GenerateDockerfile(opts GenerateOptions) (string, error) {
	port := opts.Port
	if port == 0 {
		port = 80
	}

	// Detect the document root
	docRoot := d.detectDocRoot(opts.Files)

	return fmt.Sprintf(`# Auto-generated Dockerfile for Static Site
FROM nginx:alpine

# Copy static files
COPY %s /usr/share/nginx/html

# Configure nginx for SPA routing (if needed)
RUN echo 'server { \
    listen %d; \
    server_name localhost; \
    root /usr/share/nginx/html; \
    index index.html; \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ { \
        expires 1y; \
        add_header Cache-Control "public, immutable"; \
    } \
    gzip on; \
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml; \
}' > /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE %d

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:%d/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
`, docRoot, port, port, port), nil
}

func (d *StaticDetector) detectDocRoot(files []string) string {
	// Check common build output directories
	for _, f := range files {
		switch {
		case len(f) > 5 && f[:5] == "dist/":
			return "dist"
		case len(f) > 7 && f[:7] == "public/":
			return "public"
		case len(f) > 6 && f[:6] == "build/":
			return "build"
		case len(f) > 4 && f[:4] == "out/":
			return "out"
		}
	}

	// Default to current directory
	return "."
}
