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

	"github.com/netra/backend/internal/audit"
	"github.com/netra/backend/internal/behaviour"
	"github.com/netra/backend/internal/config"
	"github.com/netra/backend/internal/device"
	"github.com/netra/backend/internal/httpapi"
	"github.com/netra/backend/internal/identity"
	"github.com/netra/backend/internal/incident"
	"github.com/netra/backend/internal/logging"
	"github.com/netra/backend/internal/policy"
	"github.com/netra/backend/internal/posture"
	"github.com/netra/backend/internal/risk"
	"github.com/netra/backend/internal/session"
	"github.com/netra/backend/internal/simulator"
	"github.com/netra/backend/internal/store"
	"github.com/netra/backend/internal/telemetry"
	"github.com/netra/backend/internal/trust"
	"github.com/netra/backend/internal/user"
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

	verifier, devVerifier, err := buildVerifier(cfg, logger)
	if err != nil {
		return err
	}

	users := user.NewStore(db.Pool())
	auditStore := audit.NewStore(db.Pool(), logger)
	devices := device.NewStore(db.Pool())
	sessions := session.NewStore(db.Pool(), devices)
	postureStore := posture.NewStore(db.Pool())
	telemetryStore := telemetry.NewStore(db.Pool())
	riskStore := risk.NewStore(db.Pool())
	policyStore := policy.NewStore(db.Pool())
	baselineStore := behaviour.NewStore(db.Pool())
	incidentStore := incident.NewStore(db.Pool())

	// A control plane with no policies would allow everything, so the shipped
	// set is seeded once to make the system safe on first boot.
	if seeded, err := policyStore.EnsureDefaults(ctx); err != nil {
		return fmt.Errorf("seed default policies: %w", err)
	} else if seeded > 0 {
		logger.Info("seeded default policies", slog.Int("count", seeded))
	}

	evaluator := trust.New(trust.Options{
		Pool:      db.Pool(),
		Engine:    risk.NewEngine(cfg.Risk.Weights, cfg.Risk.Thresholds()),
		Policies:  policyStore,
		Risks:     riskStore,
		Baselines: baselineStore,
		Postures:  postureStore,
		Incidents: incidentStore,
		Events:    telemetryStore,
		Logger:    logger,
	})

	// Replayed-request protection only needs to remember nonces for as long as
	// a captured request could still pass the clock-skew check.
	startNoncePruner(ctx, devices, sessions, logger)

	srv := &http.Server{
		Addr: cfg.HTTP.Addr,
		Handler: httpapi.NewRouter(httpapi.Options{
			Config:      cfg,
			Logger:      logger,
			DB:          db,
			Verifier:    verifier,
			Users:       users,
			Audit:       auditStore,
			AuditReader: auditStore,
			DevVerifier: devVerifier,
			Devices:     devices,
			Sessions:    sessions,
			Posture:     postureStore,

			PostureWeights:       cfg.Posture.Weights,
			ExpectedAgentVersion: cfg.Posture.ExpectedAgentVersion,

			Telemetry: telemetryStore,
			Risk:      riskStore,
			Policy:    policyStore,
			Incidents: incidentStore,
			Baselines: baselineStore,
			Trust:     evaluator,
			Stats:     trust.NewStats(db.Pool()),
			Simulator: simulator.NewRunner(db.Pool(), telemetryStore, baselineStore, postureStore, evaluator, logger),
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

// buildVerifier selects the identity verifier for this environment.
//
// Development authentication and OIDC are mutually exclusive: allowing both at
// once would mean a locally minted token could stand in for an
// organisationally issued one, which is exactly the confusion the guard in the
// configuration loader exists to prevent.
func buildVerifier(cfg *config.Config, logger *slog.Logger) (identity.Verifier, *identity.DevVerifier, error) {
	if cfg.OIDC.DevAuthEnabled {
		dev, err := identity.NewDevVerifier(string(cfg.Env), cfg.OIDC.DevAuthTTL)
		if err != nil {
			return nil, nil, fmt.Errorf("development authentication: %w", err)
		}
		logger.Warn("DEVELOPMENT AUTHENTICATION IS ENABLED",
			slog.String("issuer", dev.Issuer()),
			slog.String("detail", "tokens are minted locally by POST /api/v1/dev/token; never enable this outside development"))
		return dev, dev, nil
	}

	verifier, err := identity.NewOIDCVerifier(cfg.OIDC.Issuer, cfg.OIDC.Audience)
	if err != nil {
		return nil, nil, fmt.Errorf("identity provider: %w", err)
	}
	logger.Info("identity provider configured",
		slog.String("issuer", cfg.OIDC.Issuer),
		slog.String("audience", cfg.OIDC.Audience))
	return verifier, nil, nil
}

// startNoncePruner periodically deletes replay nonces that can no longer be
// used, so the table does not grow without bound on a busy fleet.
func startNoncePruner(ctx context.Context, devices *device.Store, sessions *session.Store, logger *slog.Logger) {
	const interval = 10 * time.Minute

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Twice the skew window, so a nonce is never forgotten while a
				// request carrying it could still be accepted.
				cutoff := time.Now().Add(-2 * device.MaxClockSkew)
				if removed, err := devices.PruneNonces(ctx, cutoff); err != nil {
					logger.Error("failed to prune replay nonces", slog.String("error", err.Error()))
				} else if removed > 0 {
					logger.Debug("pruned replay nonces", slog.Int64("removed", removed))
				}

				// Attestation challenges are unusable once expired.
				if removed, err := sessions.PruneNonces(ctx, time.Now()); err != nil {
					logger.Error("failed to prune attestation nonces", slog.String("error", err.Error()))
				} else if removed > 0 {
					logger.Debug("pruned attestation nonces", slog.Int64("removed", removed))
				}
			}
		}
	}()
}
