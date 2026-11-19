// Package testdb gives each test an isolated, migrated PostgreSQL schema.
// Tests are skipped unless IMA_TEST_DSN is set.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	imapg "github.com/ninepeach/go-ima/storage/postgres"
)

// New returns a pool whose search_path is a fresh schema. Migrate is applied
// unless raw is true. The schema is dropped when the test ends.
func New(t *testing.T, raw bool) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("IMA_TEST_DSN")
	if dsn == "" {
		t.Skip("IMA_TEST_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	schema := "ima_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	if !raw {
		if err := imapg.Migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}
