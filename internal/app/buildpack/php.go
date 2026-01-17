package buildpack

import (
	"fmt"
)

// PHPDetector detects PHP applications
type PHPDetector struct{}

// Name returns the language name
func (d *PHPDetector) Name() string {
	return "PHP"
}

// Detect checks if the project is a PHP application
func (d *PHPDetector) Detect(files []string) (bool, string) {
	if !containsFile(files, "composer.json") {
		return false, ""
	}

	// Default version
	return true, "8.3"
}

// GenerateDockerfile generates a Dockerfile for PHP applications
func (d *PHPDetector) GenerateDockerfile(opts GenerateOptions) (string, error) {
	port := opts.Port
	if port == 0 {
		port = 80
	}

	// Detect framework
	isLaravel := d.isLaravelApp(opts.Files)

	if isLaravel {
		return d.generateLaravelDockerfile(port), nil
	}

	return d.generateGenericDockerfile(port), nil
}

func (d *PHPDetector) isLaravelApp(files []string) bool {
	return containsFile(files, "artisan")
}

func (d *PHPDetector) generateGenericDockerfile(port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for PHP
FROM php:8.3-apache

WORKDIR /var/www/html

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Copy composer files first for better caching
COPY composer.json composer.lock* ./
RUN composer install --no-dev --optimize-autoloader

# Copy application code
COPY . .

# Set permissions
RUN chown -R www-data:www-data /var/www/html

# Configure Apache
RUN a]2enmod rewrite

# Expose port
EXPOSE %d

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:%d/ || exit 1

# Start Apache
CMD ["apache2-foreground"]
`, port, port)
}

func (d *PHPDetector) generateLaravelDockerfile(port int) string {
	return fmt.Sprintf(`# Auto-generated Dockerfile for Laravel
FROM php:8.3-fpm

WORKDIR /var/www/html

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Copy composer files first for better caching
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader

# Copy application code
COPY . .

# Set permissions
RUN chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

# Copy nginx config
RUN echo 'server { \
    listen %d; \
    root /var/www/html/public; \
    index index.php; \
    location / { \
        try_files $uri $uri/ /index.php?$query_string; \
    } \
    location ~ \.php$ { \
        fastcgi_pass 127.0.0.1:9000; \
        fastcgi_index index.php; \
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; \
        include fastcgi_params; \
    } \
}' > /etc/nginx/sites-available/default

# Generate app key if needed
RUN php artisan key:generate --force || true

# Cache config
RUN php artisan config:cache || true

# Expose port
EXPOSE %d

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:%d/ || exit 1

# Start supervisor (nginx + php-fpm)
CMD service php8.3-fpm start && nginx -g "daemon off;"
`, port, port, port)
}
