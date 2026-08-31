package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IngestResult reports what happened to a submitted batch.
type IngestResult struct {
	BatchID    uuid.UUID   `json:"batch_id"`
	Accepted   int         `json:"accepted"`
	Duplicates int         `json:"duplicates"`
	Rejected   []Rejection `json:"rejected,omitempty"`
	// SessionID is the session the batch was correlated to, if the device had
	// an active one. Telemetry from an unattended device has no session and is
	// still stored — it is evidence either way.
	SessionID *uuid.UUID `json:"session_id,omitempty"`
}

// Store persists and queries events.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a telemetry store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Ingest normalizes and stores a batch from one authenticated device.
//
// Events are correlated to the device's currently active session, which is how
// device-level telemetry acquires a user: the agent never learns who is signed
// in, and the backend never takes a client's word for it.
func (s *Store) Ingest(ctx context.Context, deviceID uuid.UUID, inbound []Inbound) (*IngestResult, error) {
	if len(inbound) > MaxBatchSize {
		return nil, fmt.Errorf("%w: a batch may contain at most %d events", ErrInvalidEvent, MaxBatchSize)
	}

	now := time.Now().UTC()
	result := &IngestResult{BatchID: uuid.New()}

	var sessionID, userID *uuid.UUID
	if session, user, err := s.activeSession(ctx, deviceID); err == nil {
		sessionID, userID = session, user
		result.SessionID = session
	}

	rows := make([][]any, 0, len(inbound))
	for index, candidate := range inbound {
		event, err := candidate.Normalize(deviceID, now)
		if err != nil {
			result.Rejected = append(result.Rejected, Rejection{
				EventID: candidate.EventID, Index: index, Reason: err.Error(),
			})
			continue
		}

		metadata, err := json.Marshal(event.Metadata)
		if err != nil {
			result.Rejected = append(result.Rejected, Rejection{
				EventID: candidate.EventID, Index: index, Reason: "metadata could not be encoded",
			})
			continue
		}

		rows = append(rows, []any{
			event.OccurredAt, event.ReceivedAt, deviceID, userID, sessionID,
			string(event.Type), string(event.Severity), string(event.Source),
			metadata, nullable(event.AgentEventID), result.BatchID,
		})
	}

	if len(rows) == 0 {
		return result, nil
	}

	// ON CONFLICT DO NOTHING makes a retried batch idempotent: an agent that
	// resends after a network failure inserts nothing rather than duplicating
	// an investigation timeline.
	inserted, err := s.insert(ctx, rows)
	if err != nil {
		return nil, err
	}
	result.Accepted = inserted
	result.Duplicates = len(rows) - inserted
	return result, nil
}

func (s *Store) insert(ctx context.Context, rows [][]any) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin ingest: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	batch := &pgx.Batch{}
	for _, row := range rows {
		batch.Queue(`
			INSERT INTO events (
				occurred_at, received_at, device_id, user_id, session_id,
				event_type, severity, source, metadata, agent_event_id, batch_id
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (device_id, agent_event_id) WHERE agent_event_id IS NOT NULL
			DO NOTHING`, row...)
	}

	results := tx.SendBatch(ctx, batch)
	inserted := 0
	for range rows {
		tag, err := results.Exec()
		if err != nil {
			_ = results.Close()
			return 0, fmt.Errorf("insert event: %w", err)
		}
		inserted += int(tag.RowsAffected())
	}
	if err := results.Close(); err != nil {
		return 0, fmt.Errorf("close ingest batch: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit ingest: %w", err)
	}
	return inserted, nil
}

// RecordBackendEvent stores an event the backend itself produced, such as a
// policy decision or a risk update.
func (s *Store) RecordBackendEvent(ctx context.Context, event Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode event metadata: %w", err)
	}
	now := time.Now().UTC()
	if event.OccurredAt.IsZero() {
		event.OccurredAt = now
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO events (occurred_at, received_at, device_id, user_id, session_id,
			event_type, severity, source, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		event.OccurredAt, now, event.DeviceID, event.UserID, event.SessionID,
		string(event.Type), string(event.Severity), string(event.Source), metadata)
	if err != nil {
		return fmt.Errorf("record event: %w", err)
	}
	return nil
}

// activeSession finds the device's current session, if any.
func (s *Store) activeSession(ctx context.Context, deviceID uuid.UUID) (*uuid.UUID, *uuid.UUID, error) {
	var sessionID, userID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id FROM sessions
		WHERE device_id = $1 AND status <> 'ENDED'
		ORDER BY started_at DESC LIMIT 1`, deviceID).Scan(&sessionID, &userID)
	if err != nil {
		return nil, nil, err
	}
	return &sessionID, &userID, nil
}

const eventColumns = `e.id, e.agent_event_id, e.occurred_at, e.received_at,
	e.device_id, e.user_id, e.session_id, e.event_type, e.severity, e.source,
	e.metadata, COALESCE(d.hostname, ''), COALESCE(u.display_name, '')`

// Query returns events matching a filter, newest first.
func (s *Store) Query(ctx context.Context, filter Filter) ([]Event, error) {
	filter = filter.Normalize()

	conditions := []string{"TRUE"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(clause, len(args)))
	}

	if filter.DeviceID != nil {
		add("e.device_id = $%d", *filter.DeviceID)
	}
	if filter.UserID != nil {
		add("e.user_id = $%d", *filter.UserID)
	}
	if filter.SessionID != nil {
		add("e.session_id = $%d", *filter.SessionID)
	}
	if filter.Severity != nil {
		add("e.severity = $%d", string(*filter.Severity))
	}
	if filter.Since != nil {
		add("e.occurred_at >= $%d", *filter.Since)
	}
	if len(filter.Types) > 0 {
		types := make([]string, 0, len(filter.Types))
		for _, t := range filter.Types {
			types = append(types, string(t))
		}
		add("e.event_type = ANY($%d)", types)
	}

	args = append(args, filter.Limit)
	query := `SELECT ` + eventColumns + `
		FROM events e
		LEFT JOIN devices d ON d.id = e.device_id
		LEFT JOIN users u ON u.id = e.user_id
		WHERE ` + strings.Join(conditions, " AND ") +
		fmt.Sprintf(` ORDER BY e.occurred_at DESC LIMIT $%d`, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		out = append(out, *event)
	}
	return out, rows.Err()
}

// CountByType summarises recent activity for a session, which is the input the
// behavioural baseline reads.
func (s *Store) CountByType(ctx context.Context, sessionID uuid.UUID) (map[Type]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT event_type, count(*) FROM events WHERE session_id = $1 GROUP BY event_type`,
		sessionID)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	defer rows.Close()

	counts := map[Type]int{}
	for rows.Next() {
		var (
			eventType string
			count     int
		)
		if err := rows.Scan(&eventType, &count); err != nil {
			return nil, fmt.Errorf("scan event count: %w", err)
		}
		counts[Type(eventType)] = count
	}
	return counts, rows.Err()
}

type scannable interface {
	Scan(dest ...any) error
}

func scanEvent(row scannable) (*Event, error) {
	var (
		event        Event
		agentEventID *string
		rawMetadata  []byte
		eventType    string
		severity     string
		source       string
	)
	if err := row.Scan(&event.ID, &agentEventID, &event.OccurredAt, &event.ReceivedAt,
		&event.DeviceID, &event.UserID, &event.SessionID, &eventType, &severity,
		&source, &rawMetadata, &event.DeviceHostname, &event.UserName); err != nil {
		return nil, err
	}

	event.Type, event.Severity, event.Source = Type(eventType), Severity(severity), Source(source)
	event.OccurredAt, event.ReceivedAt = event.OccurredAt.UTC(), event.ReceivedAt.UTC()
	if agentEventID != nil {
		event.AgentEventID = *agentEventID
	}
	if len(rawMetadata) > 0 {
		if err := json.Unmarshal(rawMetadata, &event.Metadata); err != nil {
			return nil, fmt.Errorf("decode event metadata: %w", err)
		}
	}
	return &event, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
