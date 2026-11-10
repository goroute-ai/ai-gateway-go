package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

var (
	version = "v1.2.0"
	commit  = "8c41c26"
	date    = "2026-11-10T00:00:00Z"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML configuration file")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("GoRoute AI Gateway %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ai-gateway] failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize the centralized enterprise structured logger
	l := logger.Init(logger.Config{
		Level:     cfg.Logging.Level,
		Format:    cfg.Logging.Format,
		AddSource: cfg.Logging.AddSource,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var repo storage.Repository
	if cfg.Storage.Mode == "postgres" {
		pool, err := storage.NewPostgresPool(ctx, cfg.Storage.PostgresDSN)
		if err != nil {
			logger.Error("Failed to connect to PostgreSQL", slog.String("error", err.Error()))
			os.Exit(1)
		}
		defer pool.Close()
		if err := storage.RunMigrationsDir(ctx, pool, "migrations"); err != nil {
			logger.Warn("Database migration notice", slog.String("error", err.Error()))
		}
		pgRepo, err := storage.NewPostgresRepository(ctx, pool)
		if err != nil {
			logger.Error("Failed to initialize PostgresRepository", slog.String("error", err.Error()))
			os.Exit(1)
		}
		repo = pgRepo
	} else {
		repo = storage.NewMemoryRepository()
	}

	var redisFabric *storage.RedisFabric
	if cfg.Storage.RedisAddr != "" {
		redisFabric = storage.NewRedisFabric(cfg.Storage.RedisAddr, cfg.Storage.RedisPass, cfg.Storage.RedisDB)
	}

	gw, err := server.New(cfg, repo, redisFabric, nil)
	if err != nil {
		logger.Error("Failed to initialize server", slog.String("error", err.Error()))
		os.Exit(1)
	}
	gw.StartWorkers(ctx)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      gw.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		l.Info("GoRoute AI Gateway listening",
			slog.String("addr", addr),
			slog.String("storage_mode", cfg.Storage.Mode),
			slog.String("log_level", cfg.Logging.Level),
			slog.String("log_format", cfg.Logging.Format),
		)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Error("HTTP server runtime error", slog.String("error", err.Error()))
		os.Exit(1)
	case sig := <-sigCh:
		logger.Info("Received OS termination signal; gracefully draining connections and flushing spend logs...",
			slog.String("signal", sig.String()),
		)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	_ = httpSrv.Shutdown(shutdownCtx)
	gw.Shutdown(shutdownCtx)
	logger.Info("GoRoute AI Gateway shutdown complete")
}
