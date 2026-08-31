package behaviour

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

// ErrNoProfile is returned when a user has no baseline yet.
var ErrNoProfile = errors.New("no behavioural profile for this user")

// Store persists and rebuilds behavioural profiles.
type Store struct{ pool *pgxpool.Pool }

// NewStore builds a behaviour store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Load returns a user's profile.
func (s *Store) Load(ctx context.Context, userID uuid.UUID) (*Profile, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT user_id, updated_at, window_days, observation_count, login_hours,
		       known_devices, known_applications, known_networks,
		       access_rate_mean, access_rate_stddev, established
		FROM behaviour_profiles WHERE user_id = $1`, userID)

	var (
		profile                        Profile
		hours, devices, apps, networks []byte
	)
	err := row.Scan(&profile.UserID, &profile.UpdatedAt, &profile.WindowDays,
		&profile.ObservationCount, &hours, &devices, &apps, &networks,
		&profile.AccessRateMean, &profile.AccessRateStdDev, &profile.Established)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, fmt.Errorf("load behaviour profile: %w", err)
	}

	var hourList []int
	if err := decode(hours, &hourList); err != nil {
		return nil, err
	}
	for i := 0; i < len(hourList) && i < 24; i++ {
		profile.LoginHours[i] = hourList[i]
	}
	if err := decode(devices, &profile.KnownDevices); err != nil {
		return nil, err
	}
	if err := decode(apps, &profile.KnownApplications); err != nil {
		return nil, err
	}
	if err := decode(networks, &profile.KnownNetworks); err != nil {
		return nil, err
	}
	profile.UpdatedAt = profile.UpdatedAt.UTC()
	return &profile, nil
}

// Save writes a profile, replacing any existing one.
func (s *Store) Save(ctx context.Context, profile Profile) error {
	hours, _ := json.Marshal(profile.LoginHours)
	devices, _ := json.Marshal(nonNil(profile.KnownDevices))
	apps, _ := json.Marshal(nonNil(profile.KnownApplications))
	networks, _ := json.Marshal(nonNil(profile.KnownNetworks))

	_, err := s.pool.Exec(ctx, `
		INSERT INTO behaviour_profiles (user_id, updated_at, window_days, observation_count,
			login_hours, known_devices, known_applications, known_networks,
			access_rate_mean, access_rate_stddev, established)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (user_id) DO UPDATE SET
			updated_at = EXCLUDED.updated_at,
			window_days = EXCLUDED.window_days,
			observation_count = EXCLUDED.observation_count,
			login_hours = EXCLUDED.login_hours,
			known_devices = EXCLUDED.known_devices,
			known_applications = EXCLUDED.known_applications,
			known_networks = EXCLUDED.known_networks,
			access_rate_mean = EXCLUDED.access_rate_mean,
			access_rate_stddev = EXCLUDED.access_rate_stddev,
			established = EXCLUDED.established`,
		profile.UserID, profile.UpdatedAt, profile.WindowDays, profile.ObservationCount,
		hours, devices, apps, networks, profile.AccessRateMean,
		profile.AccessRateStdDev, profile.Established)
	if err != nil {
		return fmt.Errorf("save behaviour profile: %w", err)
	}
	return nil
}

// Rebuild recomputes a user's baseline from their own session history.
func (s *Store) Rebuild(ctx context.Context, userID uuid.UUID, windowDays int) (*Profile, error) {
	if windowDays <= 0 {
		windowDays = DefaultWindowDays
	}
	since := time.Now().UTC().AddDate(0, 0, -windowDays)

	rows, err := s.pool.Query(ctx, `
		SELECT s.started_at, s.device_id, COALESCE(host(s.source_ip), ''),
		       (SELECT count(*) FROM events e WHERE e.session_id = s.id)
		FROM sessions s
		WHERE s.user_id = $1 AND s.started_at >= $2
		ORDER BY s.started_at`, userID, since)
	if err != nil {
		return nil, fmt.Errorf("query sessions for baseline: %w", err)
	}
	defer rows.Close()

	var observations []Observation
	for rows.Next() {
		var observation Observation
		if err := rows.Scan(&observation.StartedAt, &observation.DeviceID,
			&observation.Network, &observation.EventCount); err != nil {
			return nil, fmt.Errorf("scan session for baseline: %w", err)
		}
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	profile := Build(userID, windowDays, observations, time.Now())
	if err := s.Save(ctx, profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func decode(raw []byte, target any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode behaviour profile field: %w", err)
	}
	return nil
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
