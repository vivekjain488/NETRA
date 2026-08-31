package session

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/netra/backend/internal/device"
)

// NonceTTL bounds how long an issued attestation nonce stays usable.
//
// It is short on purpose: the whole exchange is a single sign-in round trip, so
// a longer window only widens the opportunity to capture and reuse one.
const NonceTTL = 2 * time.Minute

// HeartbeatFreshness is how recently an enrolled device must have checked in
// for it to back a new session. A device whose agent stopped reporting may no
// longer be under NETRA's observation, so it should not silently continue to
// confer trust.
const HeartbeatFreshness = 15 * time.Minute

// Status is the lifecycle state of a session.
type Status string

const (
	StatusActive     Status = "ACTIVE"
	StatusRestricted Status = "RESTRICTED"
	StatusIsolated   Status = "ISOLATED"
	StatusEnded      Status = "ENDED"
)

// Session is a bound user-and-device session.
type Session struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	DeviceID     uuid.UUID
	Status       Status
	AuthMethod   string
	Attestation  AttestationMethod
	SourceIP     string
	CurrentRisk  *int
	CurrentLevel string
	StartedAt    time.Time
	LastSeenAt   time.Time
	EndedAt      *time.Time

	// Joined for display in the SOC console.
	UserDisplayName string
	UserEmail       string
	DeviceHostname  string
	DeviceUID       string
}

// BeginRequest is a validated request to establish a session.
type BeginRequest struct {
	UserID    uuid.UUID
	Subject   string
	DeviceUID string
	Nonce     string
	Signature string
	SourceIP  string
}

// Validate checks the request shape before any database work.
func (r BeginRequest) Validate() error {
	if err := ValidateNonceFormat(r.Nonce); err != nil {
		return err
	}
	if strings.TrimSpace(r.DeviceUID) == "" || len(r.DeviceUID) > 128 {
		return fmt.Errorf("%w: device_uid is required", ErrValidation)
	}
	if strings.TrimSpace(r.Signature) == "" || len(r.Signature) > 512 {
		return fmt.Errorf("%w: attestation signature is required", ErrValidation)
	}
	return nil
}

// DeviceLookup is the device information the session module needs.
type DeviceLookup interface {
	ByUID(ctx context.Context, deviceUID string) (*device.Device, error)
}

// Store establishes and queries sessions.
type Store struct {
	pool    *pgxpool.Pool
	devices DeviceLookup
	now     func() time.Time
}

// NewStore builds a session store.
func NewStore(pool *pgxpool.Pool, devices DeviceLookup) *Store {
	return &Store{pool: pool, devices: devices, now: time.Now}
}

// IssueNonce creates a single-use attestation challenge for one user.
func (s *Store) IssueNonce(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate attestation nonce: %w", err)
	}
	expiresAt := s.now().Add(NonceTTL)

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO session_nonces (nonce, user_id, expires_at) VALUES ($1, $2, $3)`,
		nonce, userID, expiresAt); err != nil {
		return "", time.Time{}, fmt.Errorf("store attestation nonce: %w", err)
	}
	return nonce, expiresAt, nil
}

// Begin verifies a device attestation and establishes a session.
//
// The whole exchange happens in one transaction so that a nonce cannot be spent
// twice by two simultaneous attempts, and so a verified attestation never
// results in a spent nonce without a session.
func (s *Store) Begin(ctx context.Context, req BeginRequest) (*Session, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	enrolled, err := s.devices.ByUID(ctx, req.DeviceUID)
	if err != nil {
		// An unknown device is reported the same way as an unusable one: the
		// caller is already authenticated, but should still not learn which
		// device identifiers exist.
		return nil, ErrDeviceUnusable
	}
	if enrolled.State != device.StateActive {
		return nil, ErrDeviceUnusable
	}
	if enrolled.LastHeartbeatAt == nil || s.now().Sub(*enrolled.LastHeartbeatAt) > HeartbeatFreshness {
		return nil, fmt.Errorf("%w: the device agent has not reported recently", ErrDeviceUnusable)
	}

	// The signature is checked before the nonce is spent, so a forged
	// attestation cannot burn a legitimate user's challenge.
	if err := verifyAttestation(enrolled.PublicKey, req.Nonce, req.Subject, req.Signature); err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin session transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		nonceUser uuid.UUID
		usedAt    *time.Time
		expiresAt time.Time
	)
	err = tx.QueryRow(ctx,
		`SELECT user_id, used_at, expires_at FROM session_nonces WHERE nonce = $1 FOR UPDATE`,
		req.Nonce).Scan(&nonceUser, &usedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNonce
	}
	if err != nil {
		return nil, fmt.Errorf("look up attestation nonce: %w", err)
	}
	// Unknown, spent, expired and belonging-to-another-user are all the same
	// answer: distinguishing them would make this endpoint an oracle.
	if usedAt != nil || s.now().After(expiresAt) || nonceUser != req.UserID {
		return nil, ErrNonce
	}

	var sourceIP any
	if addr, err := netip.ParseAddr(req.SourceIP); err == nil {
		sourceIP = addr.String()
	}

	var created Session
	err = tx.QueryRow(ctx, `
		INSERT INTO sessions (user_id, device_id, status, auth_method, attestation, source_ip)
		VALUES ($1, $2, 'ACTIVE', 'oidc', $3, $4)
		RETURNING id, user_id, device_id, status, auth_method, attestation,
		          COALESCE(host(source_ip), ''), current_risk, COALESCE(current_level, ''),
		          started_at, last_seen_at, ended_at`,
		req.UserID, enrolled.ID, string(AttestationDeviceSignature), sourceIP).
		Scan(&created.ID, &created.UserID, &created.DeviceID, &created.Status,
			&created.AuthMethod, &created.Attestation, &created.SourceIP,
			&created.CurrentRisk, &created.CurrentLevel, &created.StartedAt,
			&created.LastSeenAt, &created.EndedAt)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE session_nonces SET used_at = now(), session_id = $1 WHERE nonce = $2`,
		created.ID, req.Nonce); err != nil {
		return nil, fmt.Errorf("consume attestation nonce: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit session: %w", err)
	}

	created.DeviceHostname = enrolled.Hostname
	created.DeviceUID = enrolled.DeviceUID
	return &created, nil
}

// End closes a session. Only the session's own owner may end it, which the
// user identifier in the predicate enforces at the database rather than in a
// separate check that could be forgotten.
func (s *Store) End(ctx context.Context, sessionID, userID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sessions SET status = 'ENDED', ended_at = now(), last_seen_at = now()
		WHERE id = $1 AND user_id = $2 AND status <> 'ENDED'`, sessionID, userID)
	if err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// Touch records that a session is still in use.
func (s *Store) Touch(ctx context.Context, sessionID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND status <> 'ENDED'`, sessionID)
	return err
}

const sessionColumns = `s.id, s.user_id, s.device_id, s.status, s.auth_method, s.attestation,
	COALESCE(host(s.source_ip), ''), s.current_risk, COALESCE(s.current_level, ''),
	s.started_at, s.last_seen_at, s.ended_at,
	u.display_name, u.email, d.hostname, d.device_uid`

// List returns sessions, most recent first.
func (s *Store) List(ctx context.Context, activeOnly bool, limit int) ([]Session, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + sessionColumns + `
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN devices d ON d.id = s.device_id`
	if activeOnly {
		query += ` WHERE s.status <> 'ENDED'`
	}
	query += ` ORDER BY s.started_at DESC LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		out = append(out, *sess)
	}
	return out, rows.Err()
}

// ByID loads one session.
func (s *Store) ByID(ctx context.Context, id uuid.UUID) (*Session, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+sessionColumns+`
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN devices d ON d.id = s.device_id
		WHERE s.id = $1`, id)
	return scanSession(row)
}

// PruneNonces removes challenges that can no longer be used.
func (s *Store) PruneNonces(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM session_nonces WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("prune attestation nonces: %w", err)
	}
	return tag.RowsAffected(), nil
}

// verifyAttestation checks the device signature over the nonce and subject.
func verifyAttestation(publicKey []byte, nonce, subject, signature string) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrAttestation
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return ErrAttestation
	}
	message := []byte(AttestationString(nonce, subject))
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, raw) {
		return ErrAttestation
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanSession(row scannable) (*Session, error) {
	var s Session
	if err := row.Scan(&s.ID, &s.UserID, &s.DeviceID, &s.Status, &s.AuthMethod,
		&s.Attestation, &s.SourceIP, &s.CurrentRisk, &s.CurrentLevel,
		&s.StartedAt, &s.LastSeenAt, &s.EndedAt, &s.UserDisplayName,
		&s.UserEmail, &s.DeviceHostname, &s.DeviceUID); err != nil {
		return nil, err
	}
	return &s, nil
}
