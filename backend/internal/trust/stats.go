package trust

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FleetSummary is the counted state of the estate.
type FleetSummary struct {
	Endpoints        int            `json:"endpoints"`
	Trusted          int            `json:"trusted"`
	AtRisk           int            `json:"at_risk"`
	ActiveSessions   int            `json:"active_sessions"`
	HighRiskSessions int            `json:"high_risk_sessions"`
	RiskDistribution map[string]int `json:"risk_distribution"`
}

// Stats counts fleet state for the SOC overview.
type Stats struct{ pool *pgxpool.Pool }

// NewStats builds a fleet statistics reader.
func NewStats(pool *pgxpool.Pool) *Stats { return &Stats{pool: pool} }

// TrustedThreshold is the device trust score at or above which an endpoint is
// counted as trusted. It matches the point at which the risk engine stops
// penalising low posture, so the console and the engine agree on the word.
const TrustedThreshold = 70

// FleetSummary counts endpoints, sessions and risk distribution in one pass.
//
// It is a single query rather than several: an overview page that issues one
// round trip per counter becomes the slowest page in the console.
func (s *Stats) FleetSummary(ctx context.Context) (*FleetSummary, error) {
	summary := &FleetSummary{RiskDistribution: map[string]int{}}

	err := s.pool.QueryRow(ctx, `
		WITH latest_posture AS (
			SELECT DISTINCT ON (device_id) device_id, trust_score
			FROM device_posture ORDER BY device_id, collected_at DESC
		)
		SELECT
			(SELECT count(*) FROM devices WHERE state = 'ACTIVE'),
			(SELECT count(*) FROM devices d JOIN latest_posture p ON p.device_id = d.id
			   WHERE d.state = 'ACTIVE' AND p.trust_score >= $1),
			(SELECT count(*) FROM devices d LEFT JOIN latest_posture p ON p.device_id = d.id
			   WHERE d.state = 'ACTIVE' AND (p.trust_score IS NULL OR p.trust_score < $1)),
			(SELECT count(*) FROM sessions WHERE status <> 'ENDED'),
			(SELECT count(*) FROM sessions WHERE status <> 'ENDED'
			   AND current_level IN ('HIGH', 'CRITICAL'))`,
		TrustedThreshold).Scan(&summary.Endpoints, &summary.Trusted, &summary.AtRisk,
		&summary.ActiveSessions, &summary.HighRiskSessions)
	if err != nil {
		return nil, fmt.Errorf("summarise fleet: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(current_level, 'UNSCORED'), count(*)
		FROM sessions WHERE status <> 'ENDED' GROUP BY 1`)
	if err != nil {
		return nil, fmt.Errorf("summarise risk distribution: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			level string
			count int
		)
		if err := rows.Scan(&level, &count); err != nil {
			return nil, fmt.Errorf("scan risk distribution: %w", err)
		}
		summary.RiskDistribution[level] = count
	}
	return summary, rows.Err()
}
