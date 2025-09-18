# Makefile for the Go Admin Tool

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=go-admin-tool

# Docker parameters
DOCKER_IMAGE_NAME=go-admin-tool
DOCKER_TAG=latest

.PHONY: all build run clean test swagger docker-build help

all: help

help:
	@echo "Makefile for Go Admin Tool"
	@echo ""
	@echo "Usage:"
	@echo "    make build           - Build the application binary"
	@echo "    make run             - Run the application"
	@echo "    make clean           - Clean up build artifacts"
	@echo "    make test            - Run tests"
	@echo "    make swagger         - Generate Swagger documentation"
	@echo "    make docker-build    - Build the Docker image"
	@echo ""

build: swagger
	@echo "Building the application..."
	@$(GOBUILD) -o $(BINARY_NAME) ./cmd/server

run: build
	@echo "Running the application..."
	@./$(BINARY_NAME)

clean:
	@echo "Cleaning up..."
	@$(GOCLEAN)
	@rm -f $(BINARY_NAME)
	@rm -rf ./docs

test:
	@echo "Running tests..."
	@$(GOTEST) ./...

swagger:
	@echo "Generating Swagger documentation..."
	@echo "Ensure you have swag installed: go install github.com/swaggo/swag/cmd/swag@latest"
	@which swag >/dev/null || (echo "swag not found in PATH. Please run: go install github.com/swaggo/swag/cmd/swag@latest" && exit 1)
	@swag init -g cmd/server/main.go

docker-build:
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE_NAME):$(DOCKER_TAG) .
