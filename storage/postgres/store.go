// Package postgres implements go-ima repositories on PostgreSQL with pgx.
//
// All tables use the ima_ prefix so go-ima can share a database with its host
// application. The pool is borrowed: Store never closes it.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	ima "github.com/ninepeach/go-ima"
)

type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type txKey struct{}

// Store provides every go-ima repository over one pool and runs use cases in
// transactions carried through context.
type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("ima/postgres: nil pool")
	}
	return &Store{pool: pool}, nil
}

// InTx runs fn in a transaction. Repositories called with the ctx passed to fn
// use that transaction. Nested calls reuse the outer transaction.
func (s *Store) InTx(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return fn(ctx)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("ima/postgres: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if err = fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("ima/postgres: commit: %w", err)
	}
	return nil
}

func (s *Store) q(ctx context.Context) querier {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}
	return s.pool
}

// Repository views. Each is a thin, typed facade over the same Store.
func (s *Store) Users() *Users       { return &Users{s} }
func (s *Store) Sessions() *Sessions { return &Sessions{s} }
func (s *Store) Devices() *Devices   { return &Devices{s} }
func (s *Store) Audit() *Audit       { return &Audit{s} }

// Repositories returns every repository go-ima needs, for ima.Options.
func (s *Store) Repositories() ima.Repositories {
	return ima.Repositories{Tx: s, Users: s.Users(), Sessions: s.Sessions(), Devices: s.Devices(), Audit: s.Audit()}
}
