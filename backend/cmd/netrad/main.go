// Command netrad is the NETRA backend control plane.
//
// It is a modular monolith (spec §16): identity, devices, telemetry, risk,
// behaviour, policy, incidents and audit are separate packages behind one
// process, so they can be split into services later without redesign.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netra/backend/internal/config"
	"github.com/netra/backend/internal/httpapi"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/store"
	"github.com/netra/backend/internal/version"
)

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet if configuration failed.
		fmt.Fprintf(os.Stderr, "netrad: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := logging.New(os.Stdout, cfg.Log.Level, cfg.Log.Format).With(
		slog.String("service", "netrad"),
		slog.String("version", version.Version),
		slog.String("env", string(cfg.Env)),
	)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting NETRA backend",
		slog.String("commit", version.Commit),
		slog.String("addr", cfg.HTTP.Addr))

	db, err := connectWithRetry(ctx, cfg.Database, logger)
	if err != nil {
		return err
	}
	defer db.Close()

	if cfg.Database.AutoMigrate {
		if err := db.Migrate(ctx, logger); err != nil {
			return fmt.Errorf("migrate schema: %w", err)
		}
	} else {
		logger.Warn("automatic migration is disabled; the schema must be applied out of band")
	}

	srv := &http.Server{
		Addr: cfg.HTTP.Addr,
		Handler: httpapi.NewRouter(httpapi.Options{
			Config: cfg,
			Logger: logger,
			DB:     db,
		}),
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("http server listening", slog.String("addr", cfg.HTTP.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections",
			slog.String("timeout", cfg.HTTP.ShutdownTimeout.String()))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}

// connectWithRetry tolerates the database not being ready yet, which is the
// normal case when the whole stack starts at once under docker compose. It
// gives up rather than starting without a database: a control plane that
// cannot record its decisions must not serve traffic.
func connectWithRetry(ctx context.Context, cfg config.DatabaseConfig, logger *slog.Logger) (*store.Store, error) {
	const (
		maxAttempts = 10
		delay       = 3 * time.Second
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		db, err := store.New(ctx, cfg)
		if err == nil {
			logger.Info("database connected", slog.Int("attempt", attempt))
			return db, nil
		}
		lastErr = err

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		logger.Warn("database not ready, retrying",
			slog.Int("attempt", attempt),
			slog.Int("max_attempts", maxAttempts),
			slog.String("error", err.Error()))

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, fmt.Errorf("database unreachable after %d attempts: %w", maxAttempts, lastErr)
}
