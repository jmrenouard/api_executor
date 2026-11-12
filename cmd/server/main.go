package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/jobs"
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

	var auditLogger *audit.AuditLogger
	var mcpServer *mcp.Server
	var jobEngine *jobs.Engine

	cleanup := func() {
		if jobEngine != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = jobEngine.Shutdown(shutdownCtx)
			cancel()
		}
		if mcpServer != nil {
			_ = mcpServer.Close()
		}
		if auditLogger != nil {
			_ = auditLogger.Close()
		}
		_ = db.Close()
		_ = logger.Close()
	}

	certManager, err := core.NewCertManager(config.Server.TLS, config.Server.Host)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize TLS certificate manager: %w", err)
	}

	auditLogger, err = audit.NewAuditLogger(config.Audit, db, logger)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize audit logger: %w", err)
	}

	authManager, err := auth.NewManager(config.Auth)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize authentication manager: %w", err)
	}

	pluginRegistry := plugins.NewEmptyRegistry()
	if config.Plugins.Enabled {
		plugins.RegisterDefaultNativePlugins(pluginRegistry, db, config.Plugins.MaxQueryRows)
		logger.Info(fmt.Sprintf("Mounted %d default native plugins in server runtime", len(pluginRegistry.List())))

		if opsPlugin, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
			if err := pluginRegistry.Register(opsPlugin); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register default declarative ops plugin: %v", err))
			}
		}
		if config.Plugins.EnableDBExposure {
			_ = pluginRegistry.RegisterOrReplace(plugins.NewDatabaseExposurePlugin(db, config.Plugins.MaxQueryRows))
		} else {
			pluginRegistry.Unregister("db-exposure")
		}
		if config.Plugins.EnableSysDiag {
			_ = pluginRegistry.RegisterOrReplace(plugins.NewSystemDiagnosticsPlugin())
		} else {
			pluginRegistry.Unregister("sys-diagnostics")
		}
		if config.Plugins.DeclarativeDir != "" {
			if _, err := os.Stat(config.Plugins.DeclarativeDir); err == nil {
				count, err := pluginRegistry.LoadDeclarativeDirectory(config.Plugins.DeclarativeDir)
				if err != nil {
					logger.Warn(fmt.Sprintf("Encountered errors loading declarative plugins from %s: %v", config.Plugins.DeclarativeDir, err))
				} else {
					logger.Info(fmt.Sprintf("Loaded %d declarative plugins from %s", count, config.Plugins.DeclarativeDir))
				}
			}
		}
	}

	mcpServer, err = mcp.NewServer(
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

	var apiEnv *api.APIEnv

	jobStore, err := jobs.NewJobStore(db)
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to initialize persistent job store, falling back to in-memory: %v", err))
		jobStore = jobs.NewMemoryJobStore()
	}

	jobExecutor := func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		switch job.Type {
		case jobs.TypeCommand:
			cmdCopy, found := apiEnv.FindCommand(job.Action)
			if !found {
				return nil, fmt.Errorf("command %q not found", job.Action)
			}
			output, err := core.ExecuteCommandWithContext(ctx, cmdCopy, job.Timeout, logWriter)
			return map[string]any{"output": output}, err
		case jobs.TypePlugin:
			if pluginRegistry == nil {
				return nil, errors.New("plugin registry is not initialized")
			}
			res, err := pluginRegistry.Execute(ctx, job.PluginID, job.Action, job.Params, job.Timeout)
			if logWriter != nil && res.Output != "" {
				_, _ = logWriter.Write([]byte(res.Output))
			}
			return res, err
		default:
			return nil, fmt.Errorf("unsupported job type: %s", job.Type)
		}
	}

	jobEngine, err = jobs.NewEngine(jobs.DefaultEngineConfig(), jobStore, auditLogger, jobExecutor)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to initialize async job engine: %w", err)
	}
	jobEngine.SetMetricsReporter(api.NewJobMetricsReporter())
	if err := jobEngine.Start(); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("failed to start async job engine: %w", err)
	}

	multiConfigMgr, err := core.NewMultiConfigManager(configPath, config)
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to initialize multi-config manager: %v", err))
	} else {
		logger.Info(fmt.Sprintf("Multi-config manager initialized with %d profiles", len(multiConfigMgr.ListProfiles())))
	}

	apiEnv = &api.APIEnv{
		Config:             config,
		MultiConfigManager: multiConfigMgr,
		Logger:             logger,
		DB:                 db,
		CertManager:        certManager,
		AuditLogger:        auditLogger,
		AuthManager:        authManager,
		PluginRegistry:     pluginRegistry,
		MCPServer:          mcpServer,
		JobEngine:          jobEngine,
		StartTime:          time.Now(),
	}

	router := api.NewRouter(apiEnv)
	return apiEnv, router, cleanup, nil
}

// buildHTTPServer constructs the configured *http.Server for either HTTPS/TLS or plain HTTP mode.
func buildHTTPServer(env *api.APIEnv, router http.Handler) (*http.Server, error) {
	serverAddr := fmt.Sprintf("%s:%d", env.Config.Server.Host, env.Config.Server.Port)
	srv := &http.Server{
		Addr:              serverAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
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

// runServer initializes all server dependencies, constructs the HTTP/HTTPS listener, traps OS termination signals, and performs graceful shutdown.
func runServer(configPath string, serveFn func(*http.Server, bool) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServerWithContext(ctx, configPath, serveFn)
}

// runServerWithContext initializes all server dependencies, starts the listener in a goroutine, and shuts down gracefully upon context cancellation or serveFn exit.
func runServerWithContext(ctx context.Context, configPath string, serveFn func(*http.Server, bool) error) error {
	apiEnv, router, cleanup, err := initializeServerEnv(configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	srv, err := buildHTTPServer(apiEnv, router)
	if err != nil {
		apiEnv.Logger.Error(err.Error())
		return err
	}

	if serveFn == nil {
		serveFn = func(s *http.Server, tlsEnabled bool) error {
			if tlsEnabled {
				return s.ListenAndServeTLS("", "")
			}
			return s.ListenAndServe()
		}
	}

	tlsEnabled := apiEnv.Config.Server.TLS.Enabled
	if tlsEnabled {
		info := apiEnv.CertManager.Info()
		apiEnv.Logger.Info(fmt.Sprintf("Starting HTTPS server on https://%s (cert SHA-256=%s, auto_generated=%v). Swagger docs at https://%s/swagger/index.html",
			srv.Addr, info.FingerprintSHA256, info.AutoGenerated, srv.Addr))
	} else {
		apiEnv.Logger.Info(fmt.Sprintf("Starting HTTP server on http://%s. Swagger docs at http://%s/swagger/index.html", srv.Addr, srv.Addr))
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveFn(srv, tlsEnabled)
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			apiEnv.Logger.Error(fmt.Sprintf("Server failed to run: %v", err))
			return err
		}
		return nil
	case <-ctx.Done():
		apiEnv.Logger.Info("Shutdown signal received, initiating graceful shutdown...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
			apiEnv.Logger.Error(fmt.Sprintf("Graceful shutdown encountered error: %v", shutdownErr))
			<-serverErr
			return fmt.Errorf("graceful shutdown failed: %w", shutdownErr)
		}
		apiEnv.Logger.Info("Server shutdown completed gracefully")

		if serveErr := <-serverErr; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	}
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
	if err := runServer(resolveConfigPath(), nil); err != nil {
		log.Fatalf("%v", err)
	}
}
