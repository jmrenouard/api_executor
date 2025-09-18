package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"

	_ "go-admin-tool/docs"
)

// @title Go Admin Tool API
// @version 1.0
// @description This is a lightweight remote administration tool.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
func main() {
	// Load configuration
	config, err := core.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := core.NewLogger(config.Logging)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	logger.Info("Logger initialized")

	// Create a dummy secure directory if it doesn't exist for demonstration.
	if config.FileServer.Enabled {
		if _, err := os.Stat(config.FileServer.SecureDir); os.IsNotExist(err) {
			logger.Info(fmt.Sprintf("Creating secure directory for demonstration: %s", config.FileServer.SecureDir))
			if err := os.MkdirAll(config.FileServer.SecureDir, 0755); err != nil {
				logger.Error(fmt.Sprintf("Failed to create secure directory: %v", err))
			}
			// Create a dummy file in the secure directory
			dummyFilePath := fmt.Sprintf("%s/dummy.txt", config.FileServer.SecureDir)
			dummyFile, err := os.Create(dummyFilePath)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create dummy file: %v", err))
			} else {
				dummyFile.WriteString("This is a dummy file for testing.")
				dummyFile.Close()
			}
		}
	}

	// Initialize database
	db, err := database.NewDB(config.Database.Path)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to database: %v", err))
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Init(); err != nil {
		logger.Error(fmt.Sprintf("Failed to initialize database schema: %v", err))
		os.Exit(1)
	}
	logger.Info("Database initialized")

	// Create API environment
	apiEnv := &api.APIEnv{
		Config: config,
		Logger: logger,
		DB:     db,
	}

	// Create router
	router := api.NewRouter(apiEnv)

	// Start server
	serverAddr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	logger.Info(fmt.Sprintf("Starting server on %s. Swagger docs at http://%s/swagger/index.html", serverAddr, serverAddr))
	if err := http.ListenAndServe(serverAddr, router); err != nil {
		logger.Error(fmt.Sprintf("Server failed to start: %v", err))
		os.Exit(1)
	}
}
