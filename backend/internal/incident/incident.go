// Package incident correlates escalations into a single investigable record.
//
// A SOC drowning in five separate alerts for one compromised session is worse
// off than one seeing a single incident with a timeline. Correlation here is
// deliberately simple: escalations on the same session belong to the same
// incident until it is closed (spec §27).
package incident

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Status is an incident's lifecycle state.
type Status string

const (
	StatusOpen          Status = "OPEN"
	StatusInvestigating Status = "INVESTIGATING"
	StatusContained     Status = "CONTAINED"
	StatusResolved      Status = "RESOLVED"
	StatusFalsePositive Status = "FALSE_POSITIVE"
)

var knownStatuses = map[Status]bool{
	StatusOpen: true, StatusInvestigating: true, StatusContained: true,
	StatusResolved: true, StatusFalsePositive: true,
}

// ParseStatus validates a status supplied by an analyst.
func ParseStatus(raw string) (Status, bool) {
	status := Status(raw)
	return status, knownStatuses[status]
}

// Incident is a correlated escalation.
type Incident struct {
	ID        uuid.UUID  `json:"id"`
	Key       string     `json:"incident_key"`
	Title     string     `json:"title"`
	Summary   string     `json:"summary,omitempty"`
	Severity  string     `json:"severity"`
	Status    Status     `json:"status"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	DeviceID  *uuid.UUID `json:"device_id,omitempty"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	PeakRisk  int        `json:"peak_risk"`
	OpenedAt  time.Time  `json:"opened_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`

	UserName   string `json:"user_name,omitempty"`
	DeviceName string `json:"device_hostname,omitempty"`
}

// Note is an analyst's annotation.
type Note struct {
	ID         uuid.UUID `json:"id"`
	AuthorName string    `json:"author_name,omitempty"`
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"created_at"`
}

// ErrNotFound is returned when an incident does not exist.
var ErrNotFound = errors.New("incident not found")

// Store persists incidents.
type Store struct{ pool *pgxpool.Pool }

// NewStore builds an incident store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// OpenOrEscalate returns the open incident for a session, creating one if there
// is none and raising its severity and peak risk if there is.
//
// The uniqueness of the incident key is what makes this safe under concurrent
// escalation: two simultaneous evaluations cannot open two incidents for the
// same session.
func (s *Store) OpenOrEscalate(ctx context.Context, sessionID, userID, deviceID uuid.UUID,
	severity string, risk int, title, summary string) (*Incident, error) {

	key := fmt.Sprintf("session-%s", sessionID.String()[:18])

	row := s.pool.QueryRow(ctx, `
		INSERT INTO incidents (incident_key, title, summary, severity, status,
			user_id, device_id, session_id, peak_risk)
		VALUES ($1,$2,NULLIF($3,''),$4,'OPEN',$5,$6,$7,$8)
		ON CONFLICT (incident_key) DO UPDATE SET
			peak_risk  = GREATEST(incidents.peak_risk, EXCLUDED.peak_risk),
			severity   = CASE WHEN EXCLUDED.peak_risk > incidents.peak_risk
			                  THEN EXCLUDED.severity ELSE incidents.severity END,
			summary    = COALESCE(NULLIF(EXCLUDED.summary, ''), incidents.summary),
			updated_at = now()
		RETURNING id, incident_key, title, COALESCE(summary, ''), severity, status,
		          user_id, device_id, session_id, peak_risk, opened_at, updated_at, closed_at`,
		key, title, summary, severity, userID, deviceID, sessionID, risk)

	created, err := scanIncident(row)
	if err != nil {
		return nil, fmt.Errorf("open incident: %w", err)
	}
	return created, nil
}

// AttachEvents links the events that make up an incident's timeline.
func (s *Store) AttachEvents(ctx context.Context, incidentID uuid.UUID, eventIDs []uuid.UUID) error {
	if len(eventIDs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for ordinal, eventID := range eventIDs {
		batch.Queue(`INSERT INTO incident_events (incident_id, event_id, ordinal)
			VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, incidentID, eventID, ordinal)
	}
	results := s.pool.SendBatch(ctx, batch)
	for range eventIDs {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return fmt.Errorf("attach incident event: %w", err)
		}
	}
	return results.Close()
}

const incidentColumns = `i.id, i.incident_key, i.title, COALESCE(i.summary, ''), i.severity,
	i.status, i.user_id, i.device_id, i.session_id, i.peak_risk, i.opened_at,
	i.updated_at, i.closed_at`

// List returns incidents, newest first.
func (s *Store) List(ctx context.Context, openOnly bool, limit int) ([]Incident, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + incidentColumns + `, COALESCE(u.display_name, ''), COALESCE(d.hostname, '')
		FROM incidents i
		LEFT JOIN users u ON u.id = i.user_id
		LEFT JOIN devices d ON d.id = i.device_id`
	if openOnly {
		query += ` WHERE i.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')`
	}
	query += ` ORDER BY i.opened_at DESC LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var out []Incident
	for rows.Next() {
		incident, err := scanIncidentWithNames(rows)
		if err != nil {
			return nil, fmt.Errorf("scan incident: %w", err)
		}
		out = append(out, *incident)
	}
	return out, rows.Err()
}

// ByID loads one incident.
func (s *Store) ByID(ctx context.Context, id uuid.UUID) (*Incident, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+incidentColumns+`, COALESCE(u.display_name, ''), COALESCE(d.hostname, '')
		FROM incidents i
		LEFT JOIN users u ON u.id = i.user_id
		LEFT JOIN devices d ON d.id = i.device_id
		WHERE i.id = $1`, id)

	found, err := scanIncidentWithNames(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load incident: %w", err)
	}
	return found, nil
}

// SetStatus updates an incident's lifecycle state.
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status Status) error {
	closed := status == StatusResolved || status == StatusFalsePositive
	tag, err := s.pool.Exec(ctx, `
		UPDATE incidents SET status = $2, updated_at = now(),
			closed_at = CASE WHEN $3 THEN now() ELSE NULL END
		WHERE id = $1`, id, string(status), closed)
	if err != nil {
		return fmt.Errorf("update incident status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AddNote records an analyst's annotation.
func (s *Store) AddNote(ctx context.Context, incidentID uuid.UUID, authorID uuid.UUID, body string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO incident_notes (incident_id, author_id, body) VALUES ($1,$2,$3)`,
		incidentID, authorID, body)
	if err != nil {
		return fmt.Errorf("add incident note: %w", err)
	}
	return nil
}

// Notes returns an incident's annotations, oldest first.
func (s *Store) Notes(ctx context.Context, incidentID uuid.UUID) ([]Note, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT n.id, COALESCE(u.display_name, ''), n.body, n.created_at
		FROM incident_notes n
		LEFT JOIN users u ON u.id = n.author_id
		WHERE n.incident_id = $1 ORDER BY n.created_at`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("query incident notes: %w", err)
	}
	defer rows.Close()

	var out []Note
	for rows.Next() {
		var note Note
		if err := rows.Scan(&note.ID, &note.AuthorName, &note.Body, &note.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan incident note: %w", err)
		}
		note.CreatedAt = note.CreatedAt.UTC()
		out = append(out, note)
	}
	return out, rows.Err()
}

// Counts summarises incidents for the overview page.
func (s *Store) Counts(ctx context.Context) (open int, critical int, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status NOT IN ('RESOLVED','FALSE_POSITIVE')),
		       count(*) FILTER (WHERE status NOT IN ('RESOLVED','FALSE_POSITIVE') AND severity = 'CRITICAL')
		FROM incidents`).Scan(&open, &critical)
	if err != nil {
		return 0, 0, fmt.Errorf("count incidents: %w", err)
	}
	return open, critical, nil
}

type scannable interface{ Scan(dest ...any) error }

func scanIncident(row scannable) (*Incident, error) {
	var (
		i      Incident
		status string
	)
	if err := row.Scan(&i.ID, &i.Key, &i.Title, &i.Summary, &i.Severity, &status,
		&i.UserID, &i.DeviceID, &i.SessionID, &i.PeakRisk, &i.OpenedAt,
		&i.UpdatedAt, &i.ClosedAt); err != nil {
		return nil, err
	}
	i.Status = Status(status)
	i.OpenedAt, i.UpdatedAt = i.OpenedAt.UTC(), i.UpdatedAt.UTC()
	return &i, nil
}

func scanIncidentWithNames(row scannable) (*Incident, error) {
	var (
		i      Incident
		status string
	)
	if err := row.Scan(&i.ID, &i.Key, &i.Title, &i.Summary, &i.Severity, &status,
		&i.UserID, &i.DeviceID, &i.SessionID, &i.PeakRisk, &i.OpenedAt,
		&i.UpdatedAt, &i.ClosedAt, &i.UserName, &i.DeviceName); err != nil {
		return nil, err
	}
	i.Status = Status(status)
	i.OpenedAt, i.UpdatedAt = i.OpenedAt.UTC(), i.UpdatedAt.UTC()
	return &i, nil
}
