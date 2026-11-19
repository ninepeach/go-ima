package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ninepeach/go-ima/audit"
)

// Audit implements audit.Recorder.
type Audit struct{ s *Store }

var _ audit.Recorder = (*Audit)(nil)

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func (r *Audit) Record(ctx context.Context, e audit.Event) error {
	meta := e.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	if _, err := r.s.q(ctx).Exec(ctx, `INSERT INTO ima_audit_events (type, user_id, session_id, ip, occurred_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)`, string(e.Type), nullUUID(e.UserID), nullUUID(e.SessionID), ipArg(e.IP), e.OccurredAt, meta); err != nil {
		return fmt.Errorf("ima/postgres: record audit event: %w", err)
	}
	return nil
}
