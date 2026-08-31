package posture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoPosture is returned when a device has never reported.
var ErrNoPosture = errors.New("no posture has been recorded for this device")

// Record is a stored posture assessment.
type Record struct {
	ID           uuid.UUID `json:"id"`
	DeviceID     uuid.UUID `json:"device_id"`
	CollectedAt  time.Time `json:"collected_at"`
	TrustScore   int       `json:"trust_score"`
	Signals      Signals   `json:"signals"`
	Factors      []Factor  `json:"factors"`
	Verified     bool      `json:"verified"`
	ModelVersion string    `json:"model_version"`
}

// Store persists posture assessments.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a posture store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Record stores one assessment.
//
// Posture is append-only history rather than a mutable field: an investigator
// needs the posture as it was at the time of an event, not only the latest
// reading (spec §11).
func (s *Store) Record(ctx context.Context, deviceID uuid.UUID, signals Signals, assessment Assessment) (*Record, error) {
	encodedSignals, err := json.Marshal(signals)
	if err != nil {
		return nil, fmt.Errorf("encode posture signals: %w", err)
	}
	encodedFactors, err := json.Marshal(assessment.Factors)
	if err != nil {
		return nil, fmt.Errorf("encode posture factors: %w", err)
	}

	var stored Record
	var rawSignals, rawFactors []byte
	err = s.pool.QueryRow(ctx, `
		INSERT INTO device_posture (device_id, trust_score, signals, factors, verified, model_version)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, device_id, collected_at, trust_score, signals, factors, verified, model_version`,
		deviceID, assessment.Score, encodedSignals, encodedFactors,
		assessment.Verified, assessment.ModelVersion).
		Scan(&stored.ID, &stored.DeviceID, &stored.CollectedAt, &stored.TrustScore,
			&rawSignals, &rawFactors, &stored.Verified, &stored.ModelVersion)
	if err != nil {
		return nil, fmt.Errorf("store posture: %w", err)
	}

	if err := decodeRecord(&stored, rawSignals, rawFactors); err != nil {
		return nil, err
	}
	stored.CollectedAt = stored.CollectedAt.UTC()
	return &stored, nil
}

// Latest returns the most recent assessment for a device.
func (s *Store) Latest(ctx context.Context, deviceID uuid.UUID) (*Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, device_id, collected_at, trust_score, signals, factors, verified, model_version
		FROM device_posture WHERE device_id = $1
		ORDER BY collected_at DESC LIMIT 1`, deviceID)

	record, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPosture
	}
	if err != nil {
		return nil, fmt.Errorf("load posture: %w", err)
	}
	return record, nil
}

// History returns recent assessments for a device, newest first.
func (s *Store) History(ctx context.Context, deviceID uuid.UUID, limit int) ([]Record, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, collected_at, trust_score, signals, factors, verified, model_version
		FROM device_posture WHERE device_id = $1
		ORDER BY collected_at DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("query posture history: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scan posture: %w", err)
		}
		out = append(out, *record)
	}
	return out, rows.Err()
}

// LatestScores returns the current trust score for every device that has
// reported, so a fleet listing can be rendered from one query rather than one
// per device.
func (s *Store) LatestScores(ctx context.Context) (map[uuid.UUID]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (device_id) device_id, trust_score
		FROM device_posture
		ORDER BY device_id, collected_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("query latest posture scores: %w", err)
	}
	defer rows.Close()

	scores := map[uuid.UUID]int{}
	for rows.Next() {
		var (
			id    uuid.UUID
			score int
		)
		if err := rows.Scan(&id, &score); err != nil {
			return nil, fmt.Errorf("scan posture score: %w", err)
		}
		scores[id] = score
	}
	return scores, rows.Err()
}

type scannable interface {
	Scan(dest ...any) error
}

func scanRecord(row scannable) (*Record, error) {
	var (
		record                 Record
		rawSignals, rawFactors []byte
	)
	if err := row.Scan(&record.ID, &record.DeviceID, &record.CollectedAt,
		&record.TrustScore, &rawSignals, &rawFactors, &record.Verified,
		&record.ModelVersion); err != nil {
		return nil, err
	}
	if err := decodeRecord(&record, rawSignals, rawFactors); err != nil {
		return nil, err
	}
	record.CollectedAt = record.CollectedAt.UTC()
	return &record, nil
}

func decodeRecord(record *Record, rawSignals, rawFactors []byte) error {
	if len(rawSignals) > 0 {
		if err := json.Unmarshal(rawSignals, &record.Signals); err != nil {
			return fmt.Errorf("decode posture signals: %w", err)
		}
	}
	if len(rawFactors) > 0 {
		if err := json.Unmarshal(rawFactors, &record.Factors); err != nil {
			return fmt.Errorf("decode posture factors: %w", err)
		}
	}
	return nil
}
