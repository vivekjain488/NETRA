package store

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/netra/backend/migrations"
)

// migrationLockID namespaces the PostgreSQL advisory lock that serialises
// migration across concurrently starting backend instances.
const migrationLockID int64 = 8_314_027_001

// Migration is one embedded schema file.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// LoadMigrations reads and orders the embedded migrations.
//
// Filenames must be NNNN_name.sql. Duplicate versions are rejected: two
// migrations claiming the same version would apply in an undefined order.
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}

	out := make([]Migration, 0, len(entries))
	seen := map[int]string{}

	for _, name := range entries {
		base := strings.TrimSuffix(name, ".sql")
		prefix, rest, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q must be named NNNN_name.sql", name)
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("migration %q has a non-numeric version prefix: %w", name, err)
		}
		if previous, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", previous, name, version)
		}
		seen[version] = name

		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}
		out = append(out, Migration{Version: version, Name: rest, SQL: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Migrate applies every migration not yet recorded, in version order.
//
// Each migration runs inside its own transaction together with the bookkeeping
// insert, so a failure can never leave the schema half-applied but recorded as
// complete. An advisory lock prevents two instances migrating at once.
func (s *Store) Migrate(ctx context.Context, logger *slog.Logger) error {
	pending, err := LoadMigrations(migrations.FS)
	if err != nil {
		return err
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", redact(err))
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrationLockID); err != nil {
			logger.Error("failed to release migration lock", slog.String("error", err.Error()))
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER     PRIMARY KEY,
			name        TEXT        NOT NULL,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("scan applied migration: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}

	count := 0
	for _, m := range pending {
		if applied[m.Version] {
			continue
		}
		if err := applyOne(ctx, conn.Conn(), m); err != nil {
			return err
		}
		logger.Info("migration applied",
			slog.Int("migration_version", m.Version),
			slog.String("name", m.Name))
		count++
	}

	if count == 0 {
		logger.Info("database schema is up to date",
			slog.Int("applied_migrations", len(applied)))
	}
	return nil
}

func applyOne(ctx context.Context, conn *pgx.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", m.Version, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("apply migration %d (%s): %w", m.Version, m.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`,
		m.Version, m.Name); err != nil {
		return fmt.Errorf("record migration %d: %w", m.Version, err)
	}
	return tx.Commit(ctx)
}
