package gateway

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed all:webui
var webUIFiles embed.FS

// ServeWebUI serves the embedded Next.js web UI
func ServeWebUI() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the requested path, removing /webui prefix
		path := strings.TrimPrefix(r.URL.Path, "/webui")
		path = strings.TrimPrefix(path, "/")
		path = strings.TrimSuffix(path, "/") // Remove trailing slash to avoid double slashes

		// Default to index.html for root path
		if path == "" {
			path = "index.html"
		}

		// Check if this is a static asset (has file extension)
		isStaticAsset := strings.Contains(path, ".") && (strings.HasPrefix(path, "_next/") ||
			strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") ||
			strings.HasSuffix(path, ".ico") || strings.HasSuffix(path, ".svg") ||
			strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".jpg") ||
			strings.HasSuffix(path, ".woff") || strings.HasSuffix(path, ".woff2"))

		// Use forward slashes for embed.FS (not filepath.Join which uses OS separators)
		// Track the actual file path found for correct content-type detection
		fullPath := "webui/" + path
		actualPath := path
		content, err := webUIFiles.ReadFile(fullPath)

		// If not found and not a static asset, try with .html extension (for Next.js routes)
		if err != nil && !isStaticAsset {
			fullPath = "webui/" + path + ".html"
			actualPath = path + ".html"
			content, err = webUIFiles.ReadFile(fullPath)
		}

		// If still not found and not a static asset, try index.html in the path directory
		if err != nil && !isStaticAsset {
			fullPath = "webui/" + path + "/index.html"
			actualPath = path + "/index.html"
			content, err = webUIFiles.ReadFile(fullPath)
		}

		// If not found in embedded files, try reading from disk (development mode)
		if err != nil {
			diskPath := filepath.Join("internal/gateway/webui", path)
			actualPath = path
			content, err = os.ReadFile(diskPath)
			if err != nil && !isStaticAsset {
				// Try with .html extension
				diskPath = filepath.Join("internal/gateway/webui", path+".html")
				actualPath = path + ".html"
				content, err = os.ReadFile(diskPath)
				if err != nil {
					// Try index.html in directory
					diskPath = filepath.Join("internal/gateway/webui", path, "index.html")
					actualPath = path + "/index.html"
					content, err = os.ReadFile(diskPath)
				}
			}
		}

		// For static assets that aren't found, return 404
		if err != nil && isStaticAsset {
			http.NotFound(w, r)
			return
		}

		// For page routes that aren't found, fallback to index.html (SPA routing)
		if err != nil {
			fullPath = "webui/index.html"
			actualPath = "index.html"
			content, err = webUIFiles.ReadFile(fullPath)
			if err != nil {
				diskPath := filepath.Join("internal/gateway/webui", "index.html")
				content, err = os.ReadFile(diskPath)
				if err != nil {
					serveWebUINotFound(w)
					return
				}
			}
		}

		// Determine content type based on actual file path (not original request path)
		contentType := getWebUIContentType(actualPath)
		w.Header().Set("Content-Type", contentType)
		w.Write(content)
	}
}

// ServeWebUIStatic serves static files from /_next/ directory
func ServeWebUIStatic() http.Handler {
	// Try embedded files first
	subFS, err := fs.Sub(webUIFiles, "webui")
	if err != nil {
		// Fallback to disk for development
		return http.FileServer(http.Dir("internal/gateway/webui"))
	}
	return http.FileServer(http.FS(subFS))
}

// serveWebUINotFound serves a not found page
func serveWebUINotFound(w http.ResponseWriter) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Web UI Not Found</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               display: flex; justify-content: center; align-items: center; height: 100vh;
               margin: 0; background: #f5f5f5; }
        .container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 16px; }
        p { color: #666; }
        code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Web UI Not Built</h1>
        <p>The web UI static files are not available.</p>
        <p>Run <code>make webui</code> to build them, then restart the daemon.</p>
    </div>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(html))
}

// getWebUIContentType determines the content type based on file extension
func getWebUIContentType(filename string) string {
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
	case strings.HasSuffix(filename, ".jpg"), strings.HasSuffix(filename, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(filename, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(filename, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(filename, ".woff"):
		return "font/woff"
	case strings.HasSuffix(filename, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(filename, ".ttf"):
		return "font/ttf"
	case strings.HasSuffix(filename, ".map"):
		return "application/json"
	default:
		return "application/octet-stream"
	}
}
