# Load Testing Dockerfile
# Multi-stage build for k6 load testing with all dependencies

# Build stage
FROM node:18-alpine AS build

WORKDIR /app

# Install k6
RUN apk add --no-cache \
    curl \
    wget \
    && wget -q -O - https://dl.k6.io/key.gpg | apk add --allow-untrusted /dev/stdin \
    && echo "https://dl.k6.io/deb stable main" > /etc/apk/repositories \
    && apk update \
    && apk add k6

# Copy load testing files
COPY load-tests/ ./load-tests/

# Create scripts directory
RUN mkdir -p load-tests/scripts

# Make scripts executable
RUN chmod +x load-tests/run.sh \
    && chmod +x load-tests/run-all.sh \
    && chmod +x load-tests/scripts/establish-baseline.sh

# Runtime stage
FROM grafana/k6:latest

WORKDIR /app

# Copy load testing files
COPY --from=build /app/load-tests/ ./load-tests/

# Copy environment template
COPY load-tests/environments/load.env.example ./load-tests/environments/load.env.example

# Set default environment
ENV BASE_URL=http://localhost:8000
ENV LOAD_TEST_API_KEY=
ENV TEST_WALLET_ADDRESS=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
ENV TEST_TX_ID=tx-load-test-placeholder

# Make scripts executable
RUN chmod +x load-tests/run.sh \
    && chmod +x load-tests/run-all.sh

# Default command
CMD ["k6", "run", "load-tests/scenarios/sustained.js"]