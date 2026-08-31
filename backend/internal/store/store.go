// Package store owns the PostgreSQL connection pool and schema migration.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netra/backend/internal/config"
)

// Store is the database handle shared by every backend module.
type Store struct {
	pool *pgxpool.Pool
}

// New opens and verifies a connection pool.
func New(ctx context.Context, cfg config.DatabaseConfig) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		// The DSN can contain a password, so it is never echoed in the error.
		return nil, fmt.Errorf("parse database url: %w", redact(err))
	}
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", redact(err))
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", redact(err))
	}
	return &Store{pool: pool}, nil
}

// Pool exposes the underlying pool to modules that need direct query access.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Ping verifies the database is reachable. It satisfies httpapi.Pinger.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is not initialised")
	}
	return s.pool.Ping(ctx)
}

// Close releases all pooled connections.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}
