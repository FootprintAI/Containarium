package gateway

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed swagger-ui
var swaggerUIFiles embed.FS

// ServeSwaggerUI serves the Swagger UI
func ServeSwaggerUI(swaggerDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the requested path
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" || path == "/" {
			path = "index.html"
		}

		// Try to read from embedded files first
		fullPath := filepath.Join("swagger-ui", path)
		content, err := swaggerUIFiles.ReadFile(fullPath)

		// If not found in embedded files, try reading from disk
		if err != nil {
			// Try reading from swagger-ui directory on disk
			diskPath := filepath.Join("internal/gateway/swagger-ui", path)
			content, err = os.ReadFile(diskPath)
			if err != nil {
				// Serve index.html as fallback
				if path != "index.html" {
					fullPath = filepath.Join("swagger-ui", "index.html")
					content, err = swaggerUIFiles.ReadFile(fullPath)
					if err != nil {
						diskPath = filepath.Join("internal/gateway/swagger-ui", "index.html")
						content, err = os.ReadFile(diskPath)
						if err != nil {
							// If still not found, serve a basic HTML page with instructions
							serveBasicSwaggerUI(w, r)
							return
						}
					}
				} else {
					serveBasicSwaggerUI(w, r)
					return
				}
			}
		}

		// Determine content type
		contentType := getContentType(path)
		w.Header().Set("Content-Type", contentType)

		// If it's the HTML file, inject our OpenAPI spec URL
		if strings.HasSuffix(path, ".html") || strings.HasSuffix(path, "index.html") {
			htmlContent := string(content)
			// Replace the default Swagger Petstore URL with our spec
			htmlContent = strings.Replace(htmlContent,
				"url: \"https://petstore.swagger.io/v2/swagger.json\"",
				"url: \"/swagger.json\"",
				1)
			// Also try alternate format
			htmlContent = strings.ReplaceAll(htmlContent,
				"https://petstore.swagger.io/v2/swagger.json",
				"/swagger.json")
			w.Write([]byte(htmlContent))
			return
		}

		w.Write(content)
	}
}

// serveBasicSwaggerUI serves a basic Swagger UI page when static files are not available
func serveBasicSwaggerUI(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Containarium API</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; padding:0; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/swagger.json",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                persistAuthorization: true
            });
        };
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// ServeSwaggerSpec serves the OpenAPI spec JSON
func ServeSwaggerSpec(swaggerDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		specPath := filepath.Join(swaggerDir, "containarium.swagger.json")

		content, err := os.ReadFile(specPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Swagger spec not found: %v", err), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(content)
	}
}

// getContentType determines the content type based on file extension
func getContentType(filename string) string {
	switch {
	case strings.HasSuffix(filename, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(filename, ".css"):
		return "text/css"
	case strings.HasSuffix(filename, ".js"):
		return "application/javascript"
	case strings.HasSuffix(filename, ".json"):
		return "application/json"
	case strings.HasSuffix(filename, ".png"):
		return "image/png"
	case strings.HasSuffix(filename, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(filename, ".ico"):
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}
