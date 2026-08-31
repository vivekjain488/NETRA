package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists policies and the decisions made under them.
type Store struct{ pool *pgxpool.Pool }

// NewStore builds a policy store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Active returns the highest enabled version of every policy.
func (s *Store) Active(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (policy_id)
		       id, policy_id, version, name, COALESCE(description, ''), priority,
		       enabled, conditions, actions, fail_mode, created_by, created_at
		FROM policies WHERE enabled
		ORDER BY policy_id, version DESC`)
	if err != nil {
		return nil, fmt.Errorf("query active policies: %w", err)
	}
	defer rows.Close()
	return scanPolicies(rows)
}

// All returns every policy version, newest first, for the policy console.
func (s *Store) All(ctx context.Context) ([]Policy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, policy_id, version, name, COALESCE(description, ''), priority,
		       enabled, conditions, actions, fail_mode, created_by, created_at
		FROM policies ORDER BY policy_id, version DESC`)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer rows.Close()
	return scanPolicies(rows)
}

// Create stores a new version of a policy.
//
// Versions are never rewritten: the next version number is derived inside the
// same statement, so a decision that cited version 3 always finds version 3.
func (s *Store) Create(ctx context.Context, p Policy, createdBy *uuid.UUID) (*Policy, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	conditions, err := json.Marshal(p.Conditions)
	if err != nil {
		return nil, fmt.Errorf("encode policy conditions: %w", err)
	}
	actions, err := json.Marshal(p.Actions)
	if err != nil {
		return nil, fmt.Errorf("encode policy actions: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO policies (policy_id, version, name, description, priority, enabled,
			conditions, actions, fail_mode, created_by)
		VALUES ($1,
		        COALESCE((SELECT max(version) + 1 FROM policies WHERE policy_id = $1), 1),
		        $2, NULLIF($3,''), $4, $5, $6, $7, $8, $9)
		RETURNING id, policy_id, version, name, COALESCE(description, ''), priority,
		          enabled, conditions, actions, fail_mode, created_by, created_at`,
		p.PolicyID, p.Name, p.Description, p.Priority, p.Enabled,
		conditions, actions, string(p.FailMode), createdBy)

	created, err := scanPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}
	return created, nil
}

// RecordDecision stores a policy decision.
func (s *Store) RecordDecision(ctx context.Context, sessionID, userID, deviceID uuid.UUID,
	riskScoreID *uuid.UUID, resourceID *uuid.UUID, result Result, incidentID *uuid.UUID) error {

	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_decisions (session_id, user_id, device_id, risk_score_id,
			resource_id, policy_id, policy_version, decision, reason, evaluated_at,
			latency_us, incident_id)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,0),$8,$9,$10,$11,$12)`,
		sessionID, userID, deviceID, riskScoreID, resourceID,
		result.PolicyID, result.PolicyVersion, string(result.Decision), result.Reason,
		result.EvaluatedAt, result.Latency.Microseconds(), incidentID)
	if err != nil {
		return fmt.Errorf("record policy decision: %w", err)
	}
	return nil
}

// DecisionRecord is a stored decision as shown in the console.
type DecisionRecord struct {
	ID            uuid.UUID `json:"id"`
	SessionID     uuid.UUID `json:"session_id"`
	UserName      string    `json:"user_name,omitempty"`
	DeviceName    string    `json:"device_hostname,omitempty"`
	PolicyID      string    `json:"policy_id,omitempty"`
	PolicyVersion int       `json:"policy_version,omitempty"`
	Decision      Decision  `json:"decision"`
	Reason        string    `json:"reason"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	LatencyUs     int       `json:"latency_us"`
}

// Decisions returns recent decisions, newest first.
func (s *Store) Decisions(ctx context.Context, sessionID *uuid.UUID, limit int) ([]DecisionRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `
		SELECT p.id, p.session_id, COALESCE(u.display_name, ''), COALESCE(d.hostname, ''),
		       COALESCE(p.policy_id, ''), COALESCE(p.policy_version, 0), p.decision,
		       p.reason, p.evaluated_at, p.latency_us
		FROM policy_decisions p
		LEFT JOIN users u ON u.id = p.user_id
		LEFT JOIN devices d ON d.id = p.device_id`
	args := []any{}
	if sessionID != nil {
		args = append(args, *sessionID)
		query += ` WHERE p.session_id = $1`
	}
	args = append(args, limit)
	query += fmt.Sprintf(` ORDER BY p.evaluated_at DESC LIMIT $%d`, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query policy decisions: %w", err)
	}
	defer rows.Close()

	var out []DecisionRecord
	for rows.Next() {
		var (
			record   DecisionRecord
			decision string
		)
		if err := rows.Scan(&record.ID, &record.SessionID, &record.UserName, &record.DeviceName,
			&record.PolicyID, &record.PolicyVersion, &decision, &record.Reason,
			&record.EvaluatedAt, &record.LatencyUs); err != nil {
			return nil, fmt.Errorf("scan policy decision: %w", err)
		}
		record.Decision = Decision(decision)
		record.EvaluatedAt = record.EvaluatedAt.UTC()
		out = append(out, record)
	}
	return out, rows.Err()
}

// EnsureDefaults seeds the shipped policy set the first time the system starts.
//
// A control plane with no policies would allow everything, so the defaults
// exist to make the system safe on first boot rather than to be authoritative.
func (s *Store) EnsureDefaults(ctx context.Context) (int, error) {
	existing, err := s.All(ctx)
	if err != nil {
		return 0, err
	}
	if len(existing) > 0 {
		return 0, nil
	}

	created := 0
	for _, candidate := range DefaultPolicies() {
		if _, err := s.Create(ctx, candidate, nil); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

type scannable interface{ Scan(dest ...any) error }

type rowIterator interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanPolicies(rows rowIterator) ([]Policy, error) {
	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func scanPolicy(row scannable) (*Policy, error) {
	var (
		p                   Policy
		conditions, actions []byte
		failMode            string
	)
	if err := row.Scan(&p.ID, &p.PolicyID, &p.Version, &p.Name, &p.Description,
		&p.Priority, &p.Enabled, &conditions, &actions, &failMode,
		&p.CreatedBy, &p.CreatedAt); err != nil {
		return nil, err
	}
	p.FailMode = FailMode(failMode)
	p.CreatedAt = p.CreatedAt.UTC()
	if err := json.Unmarshal(conditions, &p.Conditions); err != nil {
		return nil, fmt.Errorf("decode policy conditions: %w", err)
	}
	if err := json.Unmarshal(actions, &p.Actions); err != nil {
		return nil, fmt.Errorf("decode policy actions: %w", err)
	}
	return &p, nil
}
