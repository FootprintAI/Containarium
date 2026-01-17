package buildpack

import (
	"fmt"
)

// RubyDetector detects Ruby applications
type RubyDetector struct{}

// Name returns the language name
func (d *RubyDetector) Name() string {
	return "Ruby"
}

// Detect checks if the project is a Ruby application
func (d *RubyDetector) Detect(files []string) (bool, string) {
	if !containsFile(files, "Gemfile") {
		return false, ""
	}

	// Default version
	return true, "3.3"
}

// GenerateDockerfile generates a Dockerfile for Ruby applications
func (d *RubyDetector) GenerateDockerfile(opts GenerateOptions) (string, error) {
	port := opts.Port
	if port == 0 {
		port = 3000
	}

	// Detect if it's a Rails app
	isRails := d.isRailsApp(opts.Files)

	if isRails {
		return d.generateRailsDockerfile(port), nil
	}

	return d.generateGenericDockerfile(port), nil
}

func (d *RubyDetector) isRailsApp(files []string) bool {
	return containsFile(files, "config.ru") && containsFile(files, "Rakefile")
}

func (d *RubyDetector) generateGenericDockerfile(port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for Ruby
FROM ruby:3.3-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Gemfile first for better caching
COPY Gemfile Gemfile.lock* ./
RUN bundle install --without development test

# Copy application code
COPY . .

# Expose port
EXPOSE %d

# Set environment variables
ENV PORT=%d

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:%d/ || exit 1

# Start application
CMD ["ruby", "app.rb"]
`, port, port, port)
}

func (d *RubyDetector) generateRailsDockerfile(port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for Rails
FROM ruby:3.3-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Copy Gemfile first for better caching
COPY Gemfile Gemfile.lock* ./
RUN bundle install --without development test

# Copy application code
COPY . .

# Precompile assets
RUN RAILS_ENV=production bundle exec rake assets:precompile || true

# Expose port
EXPOSE %d

# Set environment variables
ENV PORT=%d
ENV RAILS_ENV=production
ENV RAILS_LOG_TO_STDOUT=true

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:%d/ || exit 1

# Start with puma
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
`, port, port, port)
}
