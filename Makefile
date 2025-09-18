.PHONY: all build clean mpcium mpc install test test-verbose test-coverage e2e-test e2e-clean cleanup-test-env

BIN_DIR := bin

# Default target
all: build

# Build both binaries
build: mpcium mpc

# Install mpcium (builds and places it in $GOBIN or $GOPATH/bin)
mpcium:
	go install ./cmd/mpcium

# Install mpcium-cli
mpc:
	go install ./cmd/mpcium-cli

# Install binaries to /usr/local/bin (auto-detects architecture)
install:
	@echo "Building and installing mpcium binaries for Linux..."
	GOOS=linux go build -o /tmp/mpcium ./cmd/mpcium
	GOOS=linux go build -o /tmp/mpcium-cli ./cmd/mpcium-cli
	sudo install -m 755 /tmp/mpcium /usr/local/bin/
	sudo install -m 755 /tmp/mpcium-cli /usr/local/bin/
	rm -f /tmp/mpcium /tmp/mpcium-cli
	@echo "Successfully installed mpcium and mpcium-cli to /usr/local/bin/"

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with coverage report
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run E2E integration tests
e2e-test: build
	@echo "Running E2E integration tests..."
	cd e2e && make test

# Run E2E tests with coverage
e2e-test-coverage: build
	@echo "Running E2E integration tests with coverage..."
	cd e2e && make test-coverage

# Clean up E2E test artifacts
e2e-clean:
	@echo "Cleaning up E2E test artifacts..."
	cd e2e && make clean

# Comprehensive cleanup of test environment (kills processes, removes artifacts)
cleanup-test-env:
	@echo "Performing comprehensive test environment cleanup..."
	cd e2e && ./cleanup_test_env.sh

# Run all tests (unit + E2E)
test-all: test e2e-test

# Wipe out manually built binaries if needed (not required by go install)
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

# Full clean (including E2E artifacts)
clean-all: clean e2e-clean

gen-configs:
	chmod +x ./deployments/base/node-configs/setup-nodes.sh
	./deployments/base/node-configs/setup-nodes.sh

run-dev:
	docker compose -f ./deployments/dev/docker-compose.yaml up -d

stop-dev:
	docker compose -f ./deployments/dev/docker-compose.yaml down