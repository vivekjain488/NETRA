package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// State is the lifecycle state of a device record.
type State string

const (
	StatePending State = "PENDING"
	StateActive  State = "ACTIVE"
	StateRevoked State = "REVOKED"
)

// KeyProtection describes how the endpoint protects its private key.
//
// "software" is the development identity of spec §11; the hardware-backed
// forms are recorded distinctly so a device's trust score can reflect the
// difference rather than treating all keys as equally protected.
const (
	KeyProtectionSoftware         = "software"
	KeyProtectionTPM              = "tpm"
	KeyProtectionWindowsCertStore = "windows-cert-store"
)

// Device is an enrolled endpoint.
type Device struct {
	ID              uuid.UUID
	DeviceUID       string
	Hostname        string
	OSName          string
	OSVersion       string
	AgentVersion    string
	PublicKey       []byte
	KeyAlgorithm    string
	KeyProtection   string
	State           State
	EnrolledAt      *time.Time
	LastHeartbeatAt *time.Time
	RevokedAt       *time.Time
	RevokedReason   string
	CreatedAt       time.Time
}

// Errors returned by the store.
var (
	ErrEnrollmentToken = errors.New("enrollment token is not valid")
	ErrDeviceExists    = errors.New("a device with this identifier is already enrolled")
	ErrDeviceNotFound  = errors.New("device not found")
	ErrDeviceNotActive = errors.New("device is not active")
	ErrReplayedNonce   = errors.New("request nonce has already been used")

	// ErrValidation wraps every rejection caused by the request itself, so the
	// HTTP layer can distinguish a caller's mistake from an infrastructure
	// failure without inspecting error strings.
	ErrValidation = errors.New("invalid request")
)

// EnrollRequest is what an agent presents at enrollment.
type EnrollRequest struct {
	DeviceUID     string
	Hostname      string
	OSName        string
	OSVersion     string
	AgentVersion  string
	PublicKey     []byte
	KeyProtection string
}

// Validate checks the fields NETRA depends on.
func (r EnrollRequest) Validate() error {
	if l := len(strings.TrimSpace(r.DeviceUID)); l < 8 || l > 128 {
		return fmt.Errorf("%w: device_uid must be between 8 and 128 characters", ErrValidation)
	}
	if strings.TrimSpace(r.Hostname) == "" || len(r.Hostname) > 255 {
		return fmt.Errorf("%w: hostname is required and must be at most 255 characters", ErrValidation)
	}
	if len(r.PublicKey) != 32 {
		return fmt.Errorf("%w: public_key must be a 32-byte Ed25519 key", ErrValidation)
	}
	switch r.KeyProtection {
	case KeyProtectionSoftware, KeyProtectionTPM, KeyProtectionWindowsCertStore:
	default:
		return fmt.Errorf("%w: key_protection must be software, tpm or windows-cert-store", ErrValidation)
	}
	for _, field := range []struct{ name, value string }{
		{"os_name", r.OSName}, {"os_version", r.OSVersion}, {"agent_version", r.AgentVersion},
	} {
		if strings.TrimSpace(field.value) == "" || len(field.value) > 128 {
			return fmt.Errorf("%w: %s is required and must be at most 128 characters", ErrValidation, field.name)
		}
	}
	return nil
}

// Store is the PostgreSQL-backed device repository.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a device store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const deviceColumns = `id, device_uid, hostname, os_name, os_version, agent_version,
	public_key, key_algorithm, key_protection, state, enrolled_at, last_heartbeat_at,
	revoked_at, COALESCE(revoked_reason, ''), created_at`

// IssueEnrollmentToken creates a single-use token and returns its plaintext.
//
// Only the SHA-256 hash is stored. A database read therefore does not yield a
// usable token, and the plaintext is returned exactly once — the same reason
// password hashes exist, applied to a credential that can enrol a device.
func (s *Store) IssueEnrollmentToken(ctx context.Context, createdBy *uuid.UUID, label string, ttl time.Duration) (string, uuid.UUID, error) {
	if ttl <= 0 || ttl > 30*24*time.Hour {
		return "", uuid.Nil, fmt.Errorf("%w: enrollment token lifetime must be between 0 and 30 days", ErrValidation)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", uuid.Nil, fmt.Errorf("generate enrollment token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))

	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO enrollment_tokens (token_hash, label, created_by, expires_at)
		VALUES ($1, NULLIF($2, ''), $3, $4)
		RETURNING id`,
		sum[:], label, createdBy, time.Now().Add(ttl)).Scan(&id)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("store enrollment token: %w", err)
	}
	return plaintext, id, nil
}

// Enroll consumes an enrollment token and registers the device.
//
// Token consumption and device creation happen in one transaction: a token
// must not be spendable twice even if two agents present it simultaneously.
func (s *Store) Enroll(ctx context.Context, token string, req EnrollRequest) (*Device, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// FOR UPDATE serialises concurrent attempts to spend the same token.
	var (
		tokenID   uuid.UUID
		usedAt    *time.Time
		expiresAt time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, used_at, expires_at FROM enrollment_tokens
		WHERE token_hash = $1 FOR UPDATE`, sum[:]).Scan(&tokenID, &usedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEnrollmentToken
	}
	if err != nil {
		return nil, fmt.Errorf("look up enrollment token: %w", err)
	}
	if usedAt != nil || time.Now().After(expiresAt) {
		// Used and expired are reported identically: distinguishing them would
		// tell an attacker whether a guessed token had ever been real.
		return nil, ErrEnrollmentToken
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO devices (
			device_uid, hostname, os_name, os_version, agent_version,
			public_key, key_algorithm, key_protection, state, enrolled_at
		) VALUES ($1,$2,$3,$4,$5,$6,'ed25519',$7,'ACTIVE',now())
		RETURNING `+deviceColumns,
		req.DeviceUID, req.Hostname, req.OSName, req.OSVersion, req.AgentVersion,
		req.PublicKey, req.KeyProtection)

	created, err := scanDevice(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// A device identifier is claimed once. Re-enrollment after a
			// reinstall produces a new identifier and a new key pair, so a
			// duplicate here means someone is trying to take over an existing
			// device record.
			return nil, ErrDeviceExists
		}
		return nil, fmt.Errorf("create device: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE enrollment_tokens SET used_at = now(), device_id = $1 WHERE id = $2`,
		created.ID, tokenID); err != nil {
		return nil, fmt.Errorf("consume enrollment token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit enrollment: %w", err)
	}
	return created, nil
}

// ByUID loads a device by its agent-generated identifier.
func (s *Store) ByUID(ctx context.Context, deviceUID string) (*Device, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE device_uid = $1`, deviceUID)
	d, err := scanDevice(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load device: %w", err)
	}
	return d, nil
}

// ByID loads a device by internal identifier.
func (s *Store) ByID(ctx context.Context, id uuid.UUID) (*Device, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = $1`, id)
	d, err := scanDevice(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load device: %w", err)
	}
	return d, nil
}

// List returns devices ordered by most recent heartbeat.
func (s *Store) List(ctx context.Context, limit int) ([]Device, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+deviceColumns+`
		FROM devices ORDER BY last_heartbeat_at DESC NULLS LAST, created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// Heartbeat records that a device is alive and updates its reported version.
func (s *Store) Heartbeat(ctx context.Context, id uuid.UUID, agentVersion string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET last_heartbeat_at = now(),
		    agent_version = COALESCE(NULLIF($2, ''), agent_version),
		    updated_at = now()
		WHERE id = $1 AND state = 'ACTIVE'`, id, agentVersion)
	if err != nil {
		return fmt.Errorf("record heartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotActive
	}
	return nil
}

// Revoke marks a device as no longer trusted.
func (s *Store) Revoke(ctx context.Context, id uuid.UUID, reason string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices
		SET state = 'REVOKED', revoked_at = now(), revoked_reason = NULLIF($2, ''), updated_at = now()
		WHERE id = $1 AND state <> 'REVOKED'`, id, reason)
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// ConsumeNonce records a request nonce, rejecting one already seen.
//
// Uniqueness is enforced by the primary key rather than by a read-then-write,
// so two concurrent replays cannot both pass a check and then both insert.
func (s *Store) ConsumeNonce(ctx context.Context, deviceID uuid.UUID, nonce string, seenAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO replay_nonces (nonce, device_id, seen_at) VALUES ($1, $2, $3)`,
		nonce, deviceID, seenAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrReplayedNonce
		}
		return fmt.Errorf("record request nonce: %w", err)
	}
	return nil
}

// PruneNonces deletes nonces older than the clock-skew window allows to be
// replayed. Retaining them indefinitely would grow without bound for no
// security benefit.
func (s *Store) PruneNonces(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM replay_nonces WHERE seen_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("prune request nonces: %w", err)
	}
	return tag.RowsAffected(), nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanDevice(row scannable) (*Device, error) {
	var (
		d     Device
		state string
	)
	if err := row.Scan(&d.ID, &d.DeviceUID, &d.Hostname, &d.OSName, &d.OSVersion,
		&d.AgentVersion, &d.PublicKey, &d.KeyAlgorithm, &d.KeyProtection, &state,
		&d.EnrolledAt, &d.LastHeartbeatAt, &d.RevokedAt, &d.RevokedReason,
		&d.CreatedAt); err != nil {
		return nil, err
	}
	d.State = State(state)
	return &d, nil
}
