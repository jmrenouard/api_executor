package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"

	_ "go-admin-tool/docs"
)

// resolveConfigPath returns CONFIG_PATH from the environment or defaults to "config.yaml".
func resolveConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("CONFIG_PATH")); p != "" {
		return p
	}
	return "config.yaml"
}

// initializeServerEnv loads configuration and initializes all subsystems (Logger, SecureDir, DB, TLS, Audit, Auth, Plugins, MCP, Router).
func initializeServerEnv(configPath string) (*api.APIEnv, http.Handler, func(), error) {
	config, err := core.LoadConfig(configPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	logger, err := core.NewLogger(config.Logging)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	logger.Info("Logger initialized")

	// Create a dummy secure directory if it doesn't exist for demonstration.
	if config.FileServer.Enabled && strings.TrimSpace(config.FileServer.SecureDir) != "" {
		if _, err := os.Stat(config.FileServer.SecureDir); os.IsNotExist(err) {
			logger.Info(fmt.Sprintf("Creating secure directory for demonstration: %s", config.FileServer.SecureDir))
			if err := os.MkdirAll(config.FileServer.SecureDir, 0755); err != nil {
				logger.Error(fmt.Sprintf("Failed to create secure directory: %v", err))
			} else {
				dummyFilePath := filepath.Join(config.FileServer.SecureDir, "dummy.txt")
				if dummyFile, err := os.Create(dummyFilePath); err == nil {
					_, _ = dummyFile.WriteString("This is a dummy file for testing.")
					_ = dummyFile.Close()
				}
			}
		}
	}

	db, err := database.NewDB(config.Database.Path)
	if err != nil {
		_ = logger.Close()
		return nil, nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if err := db.Init(); err != nil {
		_ = db.Close()
		_ = logger.Close()
		return nil, nil, nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}
	logger.Info("Database initialized")

	cleanup := func() {
		_ = db.Close()
		_ = logger.Close()
	}

	certManager, err := core.NewCertManager(config.Server.TLS, config.Server.Host)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize TLS certificate manager: %w", err)
	}

	auditLogger, err := audit.NewAuditLogger(config.Audit, db, logger)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize audit logger: %w", err)
	}

	authManager, err := auth.NewManager(config.Auth)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize authentication manager: %w", err)
	}

	pluginRegistry := plugins.NewRegistry()
	if config.Plugins.Enabled {
		if opsPlugin, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
			_ = pluginRegistry.Register(opsPlugin)
		}
		if config.Plugins.EnableDBExposure {
			_ = pluginRegistry.Register(plugins.NewDatabaseExposurePlugin(db, config.Plugins.MaxQueryRows))
		}
		if config.Plugins.EnableSysDiag {
			_ = pluginRegistry.Register(plugins.NewSystemDiagnosticsPlugin())
		}
		if config.Plugins.DeclarativeDir != "" {
			if _, err := os.Stat(config.Plugins.DeclarativeDir); err == nil {
				_, _ = pluginRegistry.LoadDeclarativeDirectory(config.Plugins.DeclarativeDir)
			}
		}
	}

	mcpServer, err := mcp.NewServer(
		config.MCP,
		config,
		db,
		certManager,
		pluginRegistry,
		auditLogger,
		logger,
		api.RecordActionCall,
	)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize MCP server: %w", err)
	}

	apiEnv := &api.APIEnv{
		Config:         config,
		Logger:         logger,
		DB:             db,
		CertManager:    certManager,
		AuditLogger:    auditLogger,
		AuthManager:    authManager,
		PluginRegistry: pluginRegistry,
		MCPServer:      mcpServer,
	}

	router := api.NewRouter(apiEnv)
	return apiEnv, router, cleanup, nil
}

// buildHTTPServer constructs the configured *http.Server for either HTTPS/TLS or plain HTTP mode.
func buildHTTPServer(env *api.APIEnv, router http.Handler) (*http.Server, error) {
	serverAddr := fmt.Sprintf("%s:%d", env.Config.Server.Host, env.Config.Server.Port)
	srv := &http.Server{
		Addr:    serverAddr,
		Handler: router,
	}
	if env.Config.Server.TLS.Enabled {
		tlsConfig, err := env.CertManager.TLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS configuration: %w", err)
		}
		srv.TLSConfig = tlsConfig
	}
	return srv, nil
}

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
	apiEnv, router, cleanup, err := initializeServerEnv(resolveConfigPath())
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer cleanup()

	srv, err := buildHTTPServer(apiEnv, router)
	if err != nil {
		apiEnv.Logger.Error(err.Error())
		os.Exit(1)
	}

	if apiEnv.Config.Server.TLS.Enabled {
		info := apiEnv.CertManager.Info()
		apiEnv.Logger.Info(fmt.Sprintf("Starting HTTPS server on https://%s (cert SHA-256=%s, auto_generated=%v). Swagger docs at https://%s/swagger/index.html",
			srv.Addr, info.FingerprintSHA256, info.AutoGenerated, srv.Addr))
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			apiEnv.Logger.Error(fmt.Sprintf("HTTPS server failed to start: %v", err))
			os.Exit(1)
		}
	} else {
		apiEnv.Logger.Info(fmt.Sprintf("Starting HTTP server on http://%s. Swagger docs at http://%s/swagger/index.html", srv.Addr, srv.Addr))
		if err := srv.ListenAndServe(); err != nil {
			apiEnv.Logger.Error(fmt.Sprintf("HTTP server failed to start: %v", err))
			os.Exit(1)
		}
	}
}
