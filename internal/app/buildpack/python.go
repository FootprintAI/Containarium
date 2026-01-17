package buildpack

import (
	"fmt"
)

// PythonDetector detects Python applications
type PythonDetector struct{}

// Name returns the language name
func (d *PythonDetector) Name() string {
	return "Python"
}

// Detect checks if the project is a Python application
func (d *PythonDetector) Detect(files []string) (bool, string) {
	hasPython := containsFile(files, "requirements.txt") ||
		containsFile(files, "Pipfile") ||
		containsFile(files, "pyproject.toml")

	if !hasPython {
		return false, ""
	}

	// Default version
	return true, "3.12"
}

// GenerateDockerfile generates a Dockerfile for Python applications
func (d *PythonDetector) GenerateDockerfile(opts GenerateOptions) (string, error) {
	pythonVersion := opts.PythonVersion
	if pythonVersion == "" {
		pythonVersion = "3.12"
	}

	port := opts.Port
	if port == 0 {
		port = 8000
	}

	// Detect framework and start command
	framework, startCommand := d.detectFramework(opts.Files)

	var dockerfile string
	switch framework {
	case "django":
		dockerfile = d.generateDjangoDockerfile(pythonVersion, port)
	case "fastapi":
		dockerfile = d.generateFastAPIDockerfile(pythonVersion, port)
	case "flask":
		dockerfile = d.generateFlaskDockerfile(pythonVersion, port)
	default:
		dockerfile = d.generateGenericDockerfile(pythonVersion, port, startCommand)
	}

	return dockerfile, nil
}

func (d *PythonDetector) detectFramework(files []string) (string, string) {
	// Check for Django
	if containsFile(files, "manage.py") {
		return "django", "python manage.py runserver 0.0.0.0:$PORT"
	}

	// Check for specific app files
	hasMain := containsFile(files, "main.py")
	hasApp := containsFile(files, "app.py")

	// Default start commands based on common patterns
	if hasMain {
		return "generic", "python main.py"
	}
	if hasApp {
		return "flask", "python app.py" // Could be Flask or generic
	}

	return "generic", "python app.py"
}

func (d *PythonDetector) generateGenericDockerfile(pythonVersion string, port int, startCommand string) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for Python
FROM python:%s-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE %d

# Set environment variables
ENV PORT=%d
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:%d/')" || exit 1

# Start application
CMD %s
`, pythonVersion, port, port, port, startCommand)
}

func (d *PythonDetector) generateFlaskDockerfile(pythonVersion string, port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for Flask
FROM python:%s-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE %d

# Set environment variables
ENV PORT=%d
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:%d/')" || exit 1

# Start with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:%d", "--workers", "4", "app:app"]
`, pythonVersion, port, port, port, port)
}

func (d *PythonDetector) generateFastAPIDockerfile(pythonVersion string, port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for FastAPI
FROM python:%s-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE %d

# Set environment variables
ENV PORT=%d
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:%d/health')" || exit 1

# Start with uvicorn for production
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "%d", "--workers", "4"]
`, pythonVersion, port, port, port, port)
}

func (d *PythonDetector) generateDjangoDockerfile(pythonVersion string, port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for Django
FROM python:%s-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput || true

# Expose port
EXPOSE %d

# Set environment variables
ENV PORT=%d
ENV DJANGO_SETTINGS_MODULE=config.settings
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:%d/')" || exit 1

# Start with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:%d", "--workers", "4", "config.wsgi:application"]
`, pythonVersion, port, port, port, port)
}
