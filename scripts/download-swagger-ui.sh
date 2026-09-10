#!/bin/bash
set -e

SWAGGER_VERSION="5.11.0"
SWAGGER_DIR="internal/gateway/swagger-ui"

echo "==> Downloading Swagger UI v${SWAGGER_VERSION}..."

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download Swagger UI
echo "==> Downloading from GitHub..."
curl -LO "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v${SWAGGER_VERSION}.tar.gz"

# Extract
echo "==> Extracting..."
tar -xzf "v${SWAGGER_VERSION}.tar.gz"

# Copy to project directory
echo "==> Copying files to ${SWAGGER_DIR}..."
cd -
rm -rf "${SWAGGER_DIR}"/*
mkdir -p "${SWAGGER_DIR}"
cp -r "${TEMP_DIR}/swagger-ui-${SWAGGER_VERSION}/dist/"* "${SWAGGER_DIR}/"

# Modify index.html to use our OpenAPI spec
echo "==> Configuring Swagger UI..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' 's|https://petstore.swagger.io/v2/swagger.json|/swagger.json|g' "${SWAGGER_DIR}/index.html"
else
    # Linux
    sed -i 's|https://petstore.swagger.io/v2/swagger.json|/swagger.json|g' "${SWAGGER_DIR}/index.html"
fi

# Clean up
rm -rf "$TEMP_DIR"

echo "==> Swagger UI installed successfully!"
echo ""
echo "Files installed in: ${SWAGGER_DIR}"
echo "File count: $(find ${SWAGGER_DIR} -type f | wc -l)"
echo ""
echo "Next steps:"
echo "  1. Rebuild the binary: go build -o bin/containariumd cmd/containariumd/main.go"
echo "  2. Start daemon: ./bin/containariumd daemon --rest --jwt-secret test-secret"
echo "  3. Access Swagger UI: http://localhost:8080/swagger-ui/"
echo ""
