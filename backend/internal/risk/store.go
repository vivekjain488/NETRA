package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists risk assessments.
type Store struct{ pool *pgxpool.Pool }

// NewStore builds a risk store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Record stores an assessment with its factors and updates the session's
// current risk, in one transaction so a session can never show a score whose
// explanation was not saved.
func (s *Store) Record(ctx context.Context, userID, deviceID uuid.UUID, a Assessment) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("begin risk transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	dimensions, err := json.Marshal(a.Dimensions)
	if err != nil {
		return uuid.Nil, fmt.Errorf("encode risk dimensions: %w", err)
	}

	var id uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO risk_scores (session_id, user_id, device_id, computed_at, score,
			level, action, dimensions, model_version, trigger_event)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,''))
		RETURNING id`,
		a.SessionID, userID, deviceID, a.ComputedAt, a.Score, string(a.Level),
		string(a.Action), dimensions, a.ModelVersion, a.TriggerEvent).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert risk score: %w", err)
	}

	batch := &pgx.Batch{}
	for _, factor := range a.Factors {
		batch.Queue(`INSERT INTO risk_factors (risk_score_id, code, label, dimension, contribution, detail)
			VALUES ($1,$2,$3,$4,$5,NULLIF($6,''))`,
			id, factor.Code, factor.Label, string(factor.Dimension), factor.Contribution, factor.Detail)
	}
	results := tx.SendBatch(ctx, batch)
	for range a.Factors {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return uuid.Nil, fmt.Errorf("insert risk factor: %w", err)
		}
	}
	if err := results.Close(); err != nil {
		return uuid.Nil, fmt.Errorf("close risk factor batch: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET current_risk = $2, current_level = $3, last_seen_at = now() WHERE id = $1`,
		a.SessionID, a.Score, string(a.Level)); err != nil {
		return uuid.Nil, fmt.Errorf("update session risk: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("commit risk: %w", err)
	}
	return id, nil
}

// Latest returns the most recent assessment for a session.
func (s *Store) Latest(ctx context.Context, sessionID uuid.UUID) (*Assessment, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, session_id, computed_at, score, level, action, dimensions, model_version,
		       COALESCE(trigger_event, '')
		FROM risk_scores WHERE session_id = $1 ORDER BY computed_at DESC LIMIT 1`, sessionID)

	assessment, id, err := scanAssessment(row)
	if err != nil {
		return nil, err
	}
	factors, err := s.factors(ctx, id)
	if err != nil {
		return nil, err
	}
	assessment.Factors = factors
	return assessment, nil
}

// History returns a session's risk over time, oldest first, which is what the
// incident timeline plots.
func (s *Store) History(ctx context.Context, sessionID uuid.UUID, limit int) ([]Assessment, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, session_id, computed_at, score, level, action, dimensions, model_version,
		       COALESCE(trigger_event, '')
		FROM risk_scores WHERE session_id = $1 ORDER BY computed_at ASC LIMIT $2`, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("query risk history: %w", err)
	}
	defer rows.Close()

	var out []Assessment
	for rows.Next() {
		assessment, _, err := scanAssessment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *assessment)
	}
	return out, rows.Err()
}

func (s *Store) factors(ctx context.Context, riskScoreID uuid.UUID) ([]Factor, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT code, label, dimension, contribution, COALESCE(detail, '')
		FROM risk_factors WHERE risk_score_id = $1 ORDER BY contribution DESC, code`, riskScoreID)
	if err != nil {
		return nil, fmt.Errorf("query risk factors: %w", err)
	}
	defer rows.Close()

	var out []Factor
	for rows.Next() {
		var (
			factor    Factor
			dimension string
		)
		if err := rows.Scan(&factor.Code, &factor.Label, &dimension,
			&factor.Contribution, &factor.Detail); err != nil {
			return nil, fmt.Errorf("scan risk factor: %w", err)
		}
		factor.Dimension = Dimension(dimension)
		out = append(out, factor)
	}
	return out, rows.Err()
}

// CountRecentIncidents counts incidents raised for a user in a recent window,
// which is the history input to the next assessment.
func (s *Store) CountRecentIncidents(ctx context.Context, userID uuid.UUID, since time.Time) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM incidents WHERE user_id = $1 AND opened_at >= $2`,
		userID, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count recent incidents: %w", err)
	}
	return count, nil
}

// CountRecentDenials counts refused access decisions for a user.
func (s *Store) CountRecentDenials(ctx context.Context, userID uuid.UUID, since time.Time) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM policy_decisions
		WHERE user_id = $1 AND evaluated_at >= $2
		  AND decision IN ('DENY', 'RESTRICT', 'ISOLATE')`, userID, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count recent denials: %w", err)
	}
	return count, nil
}

type scannable interface{ Scan(dest ...any) error }

func scanAssessment(row scannable) (*Assessment, uuid.UUID, error) {
	var (
		assessment    Assessment
		id            uuid.UUID
		level, action string
		dimensions    []byte
	)
	if err := row.Scan(&id, &assessment.SessionID, &assessment.ComputedAt,
		&assessment.Score, &level, &action, &dimensions,
		&assessment.ModelVersion, &assessment.TriggerEvent); err != nil {
		return nil, uuid.Nil, err
	}
	assessment.Level, assessment.Action = Level(level), Action(action)
	assessment.ComputedAt = assessment.ComputedAt.UTC()
	if len(dimensions) > 0 {
		if err := json.Unmarshal(dimensions, &assessment.Dimensions); err != nil {
			return nil, uuid.Nil, fmt.Errorf("decode risk dimensions: %w", err)
		}
	}
	return &assessment, id, nil
}

// ErrNoAssessment is returned when a session has never been scored.
var ErrNoAssessment = pgx.ErrNoRows
