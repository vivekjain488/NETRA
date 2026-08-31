package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// chainLockID serialises appends so two concurrent writers cannot both build
// on the same predecessor and fork the chain.
const chainLockID int64 = 8_314_027_002

// Recorder appends entries to the audit log.
type Recorder interface {
	Record(ctx context.Context, entry Entry) error
}

// Store is the PostgreSQL-backed audit log.
type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewStore builds an audit store.
func NewStore(pool *pgxpool.Pool, logger *slog.Logger) *Store {
	return &Store{pool: pool, logger: logger}
}

// Record appends one entry, linking it to the current head of the chain.
func (s *Store) Record(ctx context.Context, entry Entry) error {
	if entry.At.IsZero() {
		entry.At = time.Now()
	}
	entry = entry.Normalize()

	if entry.Action == "" || entry.ActorType == "" {
		return errors.New("audit entry requires an action and an actor type")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin audit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Held for the life of the transaction; released automatically on commit
	// or rollback, so a crashed writer cannot wedge the log.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, chainLockID); err != nil {
		return fmt.Errorf("lock audit chain: %w", err)
	}

	var prevHash []byte
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_logs ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read audit chain head: %w", err)
	}

	hash, err := ComputeHash(prevHash, entry)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs (
			at, actor_type, actor_id, action, target_type, target_id,
			result, request_id, source_ip, detail, prev_hash, hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		entry.At, string(entry.ActorType), nullable(entry.ActorID), entry.Action,
		nullable(entry.TargetType), nullable(entry.TargetID), string(entry.Result),
		nullable(entry.RequestID), nullable(entry.SourceIP), entry.Detail,
		prevHash, hash,
	)
	if err != nil {
		return fmt.Errorf("insert audit record: %w", err)
	}
	return tx.Commit(ctx)
}

// List returns records in ascending sequence order, starting after afterSeq.
func (s *Store) List(ctx context.Context, afterSeq int64, limit int) ([]Record, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT seq, at, actor_type, actor_id, action, target_type, target_id,
		       result, request_id, host(source_ip), detail, prev_hash, hash
		FROM audit_logs
		WHERE seq > $1
		ORDER BY seq ASC
		LIMIT $2`, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var (
			r          Record
			actorID    *string
			targetType *string
			targetID   *string
			requestID  *string
			sourceIP   *string
			actorType  string
			result     string
		)
		if err := rows.Scan(&r.Seq, &r.At, &actorType, &actorID, &r.Action,
			&targetType, &targetID, &result, &requestID, &sourceIP,
			&r.Detail, &r.PrevHash, &r.Hash); err != nil {
			return nil, fmt.Errorf("scan audit record: %w", err)
		}
		r.ActorType = ActorType(actorType)
		r.Result = Result(result)
		r.ActorID = deref(actorID)
		r.TargetType = deref(targetType)
		r.TargetID = deref(targetID)
		r.RequestID = deref(requestID)
		r.SourceIP = deref(sourceIP)
		r.At = r.At.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// Verify walks the entire chain and reports the first broken link.
func (s *Store) Verify(ctx context.Context) error {
	const page = 500
	var (
		after int64
		prev  []byte
	)

	for {
		records, err := s.List(ctx, after, page)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return nil
		}

		// Continue from the previous page's head so a chain spanning page
		// boundaries is verified without a gap.
		if err := VerifyChainFrom(prev, records); err != nil {
			return err
		}

		last := records[len(records)-1]
		prev = last.Hash
		after = last.Seq
	}
}

// Log records an entry, reporting failure without aborting the caller.
//
// An audit write must never be the reason a security decision fails to be
// applied — but a failure to record one is itself a serious event, so it is
// logged at error level for alerting.
func Log(ctx context.Context, recorder Recorder, logger *slog.Logger, entry Entry) {
	if recorder == nil {
		return
	}
	if err := recorder.Record(ctx, entry); err != nil {
		logger.Error("failed to write audit record",
			slog.String("action", entry.Action),
			slog.String("error", err.Error()))
	}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
