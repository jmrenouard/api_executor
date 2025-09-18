package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

// APIEnv holds dependencies for API handlers.
type APIEnv struct {
	Config *core.Config
	Logger *core.Logger
	DB     *database.DB
}

// ExecuteCommandRequest defines the structure for the command execution request body.
type ExecuteCommandRequest struct {
	Name string `json:"name"`
}

// ExecuteCommandResponse defines the structure for the command execution response.
type ExecuteCommandResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// FileListResponse defines the structure for the file list response.
type FileListResponse struct {
	Files []string `json:"files"`
}

// ErrorResponse defines a generic error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ExecuteCommandHandler godoc
// @Summary Execute a predefined command
// @Description Executes a command that is predefined in the server's configuration.
// @Tags commands
// @Accept  json
// @Produce  json
// @Param   command  body  ExecuteCommandRequest  true  "Command to execute"
// @Success 200 {object} ExecuteCommandResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/execute [post]
func (env *APIEnv) ExecuteCommandHandler(w http.ResponseWriter, r *http.Request) {
	var req ExecuteCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var cmdDef *core.CommandDefinition
	for _, cmd := range env.Config.Executor.Commands {
		if cmd.Name == req.Name {
			cmdDef = &cmd
			break
		}
	}

	if cmdDef == nil {
		http.Error(w, "Command not found", http.StatusNotFound)
		return
	}

	output, err := core.ExecuteCommand(*cmdDef)
	status := "success"
	errMsg := ""
	if err != nil {
		status = "failure"
		errMsg = err.Error()
	}

	if _, dbErr := env.DB.RecordAction(req.Name, status, output); dbErr != nil {
		env.Logger.Error(fmt.Sprintf("Failed to record action to database: %v", dbErr))
		// Do not fail the request, but log the error.
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	json.NewEncoder(w).Encode(ExecuteCommandResponse{Output: output, Error: errMsg})
}


// ListFilesHandler godoc
// @Summary List files in the secure directory
// @Description Retrieves a list of files available for download from the configured secure directory.
// @Tags files
// @Produce  json
// @Success 200 {object} FileListResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/files [get]
func (env *APIEnv) ListFilesHandler(w http.ResponseWriter, r *http.Request) {
	if !env.Config.FileServer.Enabled {
		http.Error(w, "File server is disabled", http.StatusNotFound)
		return
	}

	files, err := os.ReadDir(env.Config.FileServer.SecureDir)
	if err != nil {
		http.Error(w, "Could not list files", http.StatusInternalServerError)
		return
	}

	var fileNames []string
	for _, file := range files {
		if !file.IsDir() {
			fileNames = append(fileNames, file.Name())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(FileListResponse{Files: fileNames})
}

// DownloadFileHandler godoc
// @Summary Download a file from the secure directory
// @Description Downloads a specific file from the configured secure directory.
// @Tags files
// @Param   filename  path  string  true  "Filename to download"
// @Success 200 {file} binary
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/files/{filename} [get]
func (env *APIEnv) DownloadFileHandler(w http.ResponseWriter, r *http.Request) {
    if !env.Config.FileServer.Enabled {
		http.Error(w, "File server is disabled", http.StatusNotFound)
		return
	}

	// Extract filename from URL path, e.g., /api/v1/files/myfile.log -> myfile.log
	fileName := strings.TrimPrefix(r.URL.Path, "/api/v1/files/")

	// Security: Prevent directory traversal attacks.
	if strings.Contains(fileName, "..") || strings.Contains(fileName, "/") || strings.Contains(fileName, "\\") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(env.Config.FileServer.SecureDir, fileName)

	// Security: Double-check that the resolved path is still within the secure directory.
	absSecureDir, err := filepath.Abs(env.Config.FileServer.SecureDir)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !strings.HasPrefix(absFilePath, absSecureDir) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Check if file exists
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, filePath)
}

// ListCommandsHandler godoc
// @Summary List available commands
// @Description Retrieves a list of commands that are available to be executed.
// @Tags commands
// @Produce  json
// @Success 200 {object} core.ExecutorConfig
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/commands [get]
func (env *APIEnv) ListCommandsHandler(w http.ResponseWriter, r *http.Request) {
	if !env.Config.Executor.Enabled {
		http.Error(w, "Command executor is disabled", http.StatusNotFound)
		return
	}

	// To avoid exposing the full command details, we only return the names.
	type commandInfo struct {
		Name string `json:"name"`
	}
	var commands []commandInfo
	for _, c := range env.Config.Executor.Commands {
		commands = append(commands, commandInfo{Name: c.Name})
	}

	response := struct {
		Commands []commandInfo `json:"commands"`
	}{
		Commands: commands,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
