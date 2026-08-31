// Package user owns NETRA's local record of a person.
//
// NETRA is not the source of truth for identity: the identity provider is.
// This package keeps a local projection so that events, sessions and audit
// records can reference a stable internal identifier even after a person's
// email or display name changes upstream.
package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netra/backend/internal/identity"
)

// User is the local projection of an identity-provider subject.
type User struct {
	ID              uuid.UUID
	ExternalSubject string
	Email           string
	DisplayName     string
	Department      string
	Role            identity.Role
	Disabled        bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ErrDisabled is returned when a disabled user presents a valid token.
// Disabling must take effect immediately rather than waiting for the token to
// expire.
var ErrDisabled = errors.New("user account is disabled")

// Resolver turns verified claims into a local user record.
type Resolver interface {
	ResolveFromClaims(ctx context.Context, claims *identity.Claims) (*User, error)
}

// Store is the PostgreSQL-backed user repository.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a user store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const selectColumns = `id, external_subject, email, display_name,
	COALESCE(department, ''), role, disabled_at, created_at, updated_at`

// ResolveFromClaims upserts the local record for the token's subject.
//
// The identity provider is authoritative for the role, so it is refreshed on
// every resolution: revoking ADMIN upstream takes effect on the next request
// rather than whenever a cached copy happens to expire.
func (s *Store) ResolveFromClaims(ctx context.Context, claims *identity.Claims) (*User, error) {
	if claims == nil || strings.TrimSpace(claims.Subject) == "" {
		return nil, fmt.Errorf("claims have no subject")
	}

	email := claims.Email
	if email == "" {
		// The schema requires an email; a subject-derived placeholder keeps a
		// tokenless-email provider working without inventing a real address.
		email = claims.Subject + "@unknown.invalid"
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO users (external_subject, email, display_name, department, role)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5)
		ON CONFLICT (external_subject) DO UPDATE SET
			email        = EXCLUDED.email,
			display_name = EXCLUDED.display_name,
			department   = EXCLUDED.department,
			role         = EXCLUDED.role,
			updated_at   = now()
		RETURNING `+selectColumns,
		claims.Subject, email, claims.DisplayName, claims.Department,
		string(claims.HighestRole()))

	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("upsert user: %w", err)
	}
	if u.Disabled {
		return nil, ErrDisabled
	}
	return u, nil
}

// ByID loads a user by internal identifier.
func (s *Store) ByID(ctx context.Context, id uuid.UUID) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+selectColumns+` FROM users WHERE id = $1`, id)
	u, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	return u, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanUser(row scannable) (*User, error) {
	var (
		u          User
		role       string
		disabledAt *time.Time
	)
	if err := row.Scan(&u.ID, &u.ExternalSubject, &u.Email, &u.DisplayName,
		&u.Department, &role, &disabledAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}

	parsed, ok := identity.ParseRole(role)
	if !ok {
		// A role in the database that NETRA no longer recognises must not be
		// treated as authority; fall back to the least privileged role.
		parsed = identity.RoleUser
	}
	u.Role = parsed
	u.Disabled = disabledAt != nil
	return &u, nil
}
