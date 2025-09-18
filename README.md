# Go Admin Tool

Go Admin Tool is a lightweight, self-contained web application for remote system administration. It allows you to execute predefined commands and securely access files on a server through a simple JSON API and a web interface.

## Features

-   **Performant JSON API**: A RESTful API for all functionalities.
-   **Simple Frontend**: A user-friendly web interface built with Alpine.js and Tailwind CSS.
-   **YAML Configuration**: All settings are managed through a `config.yaml` file.
-   **Command Executor**: Securely execute predefined shell commands.
-   **File Server**: List and download files from a secure, configurable directory.
-   **JSON Logging**: Structured logging for easy parsing and monitoring.
-   **Action History**: Auditable history of all executed commands stored in an SQLite database.
-   **Swagger/OpenAPI Docs**: Automatically generated API documentation.
-   **Prometheus Metrics**: Exposes application metrics for monitoring.
-   **Dockerized**: Comes with a multi-stage `Dockerfile` for easy deployment.

## Project Structure

```
.
├── cmd/server/main.go      # Main application entry point
├── config.yaml             # Application configuration
├── internal/               # Internal application code
│   ├── api/                # API handlers and router
│   ├── core/               # Core business logic (config, logger, executor)
│   └── database/           # Database logic (SQLite)
├── web/static/             # Frontend assets (HTML, JS, CSS)
├── Dockerfile              # For building the Docker container
├── Makefile                # For development tasks
└── README.md
```

## Prerequisites

-   Go (latest stable version)
-   Docker (for containerization)
-   `make` (for using the Makefile)

## Installation

1.  **Clone the repository:**
    ```sh
    git clone <repository-url>
    cd go-admin-tool
    ```

2.  **Install dependencies:**
    The project uses Go modules. Dependencies will be downloaded automatically on build.

## Configuration

The application is configured using the `config.yaml` file. Here is an example with explanations:

```yaml
server:
  port: 8080
  host: "0.0.0.0"

logging:
  level: "info" # Log level: "debug", "info", "warn", "error"
  path: "app.log" # Path to the log file. Leave empty for stdout.

database:
  path: "history.db" # Path to the SQLite database file.

file_server:
  enabled: true
  secure_dir: "/var/log/secure_files" # Directory for file listing and downloads.

command_executor:
  enabled: true
  commands:
    - name: "list-processes"
      command: "ps"
      args: ["aux"]
    - name: "disk-usage"
      command: "df"
      args: ["-h"]
```

## Usage

### Running the application

You can use the `Makefile` to build and run the application.

-   **Run the application:**
    ```sh
    make run
    ```
    This will build the binary and start the server. The application will be available at `http://localhost:8080`.

-   **Build the binary:**
    ```sh
    make build
    ```
    This creates a binary named `go-admin-tool` in the project root.

### Available `make` commands

-   `make help`: Shows a list of all available commands.
-   `make build`: Builds the application.
-   `make run`: Runs the application.
-   `make clean`: Cleans up build artifacts.
-   `make test`: Runs tests.
-   `make swagger`: Generates the Swagger API documentation.
-   `make docker-build`: Builds the Docker image.

## API Documentation

The API documentation is automatically generated from the source code using `swaggo/swag`.

-   **View the documentation:**
    Once the server is running, you can access the Swagger UI at:
    `http://localhost:8080/swagger/index.html`

-   **Generate the documentation:**
    To regenerate the documentation after making changes to the API, run:
    ```sh
    make swagger
    ```

## Docker

The application can be easily containerized using the provided `Dockerfile`.

1.  **Build the Docker image:**
    ```sh
    make docker-build
    ```
    This will create a Docker image named `go-admin-tool:latest`.

2.  **Run the Docker container:**
    ```sh
    docker run -p 8080:8080 -v $(pwd)/data:/app/data go-admin-tool:latest
    ```
    Note: It's recommended to mount a volume for persistent data (like the database and logs). You can modify the `config.yaml` to point to paths within the mounted volume.

## Prometheus Metrics

The application exposes metrics in the Prometheus text format at the `/metrics` endpoint. You can use this to monitor the application's performance.

-   **Endpoint**: `http://localhost:8080/metrics`
-   **Metrics exposed**:
    -   `http_requests_total`: A counter for the total number of HTTP requests.
    -   `http_request_duration_seconds`: A histogram of request latencies.
