# Buildpacks - Auto-Generated Dockerfiles

When you deploy an application without a Dockerfile, Containarium automatically detects your programming language and generates an appropriate Dockerfile. This document describes the detection rules and generated Dockerfiles for each supported language.

## Detection Priority

Languages are detected in this order (first match wins):

1. **Node.js** - `package.json`
2. **Python** - `requirements.txt`, `Pipfile`, or `pyproject.toml`
3. **Go** - `go.mod`
4. **Rust** - `Cargo.toml`
5. **Ruby** - `Gemfile`
6. **PHP** - `composer.json`
7. **Static** - `index.html`

If multiple marker files exist, the first matching language in this list is used.

## Node.js

**Detection:** `package.json` in project root

**Auto-detected Settings:**
- Node version: From `engines.node` in package.json, or defaults to `20`
- Start command: Based on presence of `server.js`, `index.js`, `app.js`, `main.js`, or defaults to `npm start`
- Next.js detection: Automatically detected via `next.config.*` files

### Standard Node.js App

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/', (r) => process.exit(r.statusCode === 200 ? 0 : 1))" || exit 1
CMD ["npm", "start"]
```

### Next.js App

For Next.js projects, a multi-stage build is generated:

```dockerfile
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV production
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
EXPOSE 3000
CMD ["node", "server.js"]
```

**Requirements:**
- Set `output: 'standalone'` in `next.config.js` for standalone builds

## Python

**Detection:** `requirements.txt`, `Pipfile`, or `pyproject.toml`

**Auto-detected Settings:**
- Python version: Defaults to `3.12`
- Framework detection: Flask, Django, FastAPI

### Flask App

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "app:app"]
```

### Django App

Detected by presence of `manage.py`:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python manage.py collectstatic --noinput || true
EXPOSE 8000
ENV DJANGO_SETTINGS_MODULE=config.settings
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "config.wsgi:application"]
```

### FastAPI App

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

**Note:** Install `gunicorn` or `uvicorn` in your requirements.txt for production deployments.

## Go

**Detection:** `go.mod` in project root

**Auto-detected Settings:**
- Go version: From `go.mod`, or defaults to `1.22`
- Main package: Detected from `main.go` location (`./`, `./cmd/server`, `./cmd/app`)

### Generated Dockerfile (Multi-stage)

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /app/server .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
```

**Features:**
- Multi-stage build for minimal image size
- Static binary (no CGO)
- Includes CA certificates for HTTPS
- Timezone data included

## Rust

**Detection:** `Cargo.toml` in project root

```dockerfile
FROM rust:1.75 AS builder
WORKDIR /app
RUN USER=root cargo new --bin app
WORKDIR /app/app
COPY Cargo.toml Cargo.lock* ./
RUN cargo build --release
RUN rm src/*.rs
COPY src ./src
RUN rm ./target/release/deps/app*
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/app/target/release/app ./app
EXPOSE 8080
CMD ["./app"]
```

**Features:**
- Dependency caching for faster builds
- Multi-stage build
- Minimal runtime image

## Ruby

**Detection:** `Gemfile` in project root

### Rails App

Detected by presence of `config.ru` and `Rakefile`:

```dockerfile
FROM ruby:3.3-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev nodejs npm && rm -rf /var/lib/apt/lists/*
COPY Gemfile Gemfile.lock* ./
RUN bundle install --without development test
COPY . .
RUN RAILS_ENV=production bundle exec rake assets:precompile || true
EXPOSE 3000
ENV RAILS_ENV=production
ENV RAILS_LOG_TO_STDOUT=true
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
```

### Generic Ruby App

```dockerfile
FROM ruby:3.3-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
COPY Gemfile Gemfile.lock* ./
RUN bundle install --without development test
COPY . .
EXPOSE 3000
CMD ["ruby", "app.rb"]
```

## PHP

**Detection:** `composer.json` in project root

### Laravel App

Detected by presence of `artisan`:

```dockerfile
FROM php:8.3-fpm
WORKDIR /var/www/html
RUN apt-get update && apt-get install -y --no-install-recommends libpng-dev libonig-dev libxml2-dev zip unzip nginx supervisor && rm -rf /var/lib/apt/lists/*
RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader
COPY . .
RUN chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache
RUN php artisan key:generate --force || true
RUN php artisan config:cache || true
EXPOSE 80
CMD service php8.3-fpm start && nginx -g "daemon off;"
```

### Generic PHP App

```dockerfile
FROM php:8.3-apache
WORKDIR /var/www/html
RUN apt-get update && apt-get install -y --no-install-recommends libpng-dev libonig-dev libxml2-dev zip unzip && rm -rf /var/lib/apt/lists/*
RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock* ./
RUN composer install --no-dev --optimize-autoloader
COPY . .
RUN chown -R www-data:www-data /var/www/html
RUN a2enmod rewrite
EXPOSE 80
CMD ["apache2-foreground"]
```

## Static Sites

**Detection:** `index.html` in project root or common build directories (`dist/`, `public/`, `build/`, `out/`)

```dockerfile
FROM nginx:alpine
COPY . /usr/share/nginx/html
RUN echo 'server { \
    listen 80; \
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
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**Features:**
- SPA routing support (fallback to index.html)
- Asset caching headers
- Gzip compression

**Auto-detected document root:**
- `dist/` - Common for Vite, Webpack
- `public/` - Common for Create React App
- `build/` - Common for various frameworks
- `out/` - Common for Next.js static export
- `.` - If index.html is in root

## Customizing Buildpacks

### Override Version

Specify language versions during deployment:

```bash
containarium app deploy myapp --source . \
  --buildpack-node-version 18 \
  --server <host:port> --user <username>
```

### Provide Your Own Dockerfile

For full control, create a `Dockerfile` in your project root. Containarium will use it instead of auto-generating one.

## Tips for Best Results

1. **Lock your dependencies**: Use lock files (package-lock.json, Pipfile.lock, go.sum, etc.)
2. **Use .dockerignore**: Exclude unnecessary files from the build context
3. **Set explicit ports**: Ensure your app listens on the expected port
4. **Handle environment variables**: Read config from environment variables
5. **Implement health checks**: Add a `/health` endpoint for monitoring
