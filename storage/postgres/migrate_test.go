package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ninepeach/go-ima/internal/testdb"
	imapg "github.com/ninepeach/go-ima/storage/postgres"
)

func TestMigrateIdempotentAndConcurrent(t *testing.T) {
	pool := testdb.New(t, true)
	ctx := context.Background()
	if _, err := imapg.CheckSchema(ctx, pool); !errors.Is(err, imapg.ErrSchemaOutdated) {
		t.Fatalf("fresh database: want ErrSchemaOutdated, got %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- imapg.Migrate(ctx, pool) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := imapg.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	v, err := imapg.CheckSchema(ctx, pool)
	if err != nil || v != imapg.SchemaVersion() {
		t.Fatalf("version %d err %v", v, err)
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	pool := testdb.New(t, false)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO ima_schema_migrations (version) VALUES ($1)`, imapg.SchemaVersion()+1); err != nil {
		t.Fatal(err)
	}
	if err := imapg.Migrate(ctx, pool); !errors.Is(err, imapg.ErrSchemaTooNew) {
		t.Fatalf("want ErrSchemaTooNew, got %v", err)
	}
	if _, err := imapg.CheckSchema(ctx, pool); err != nil {
		t.Fatalf("newer schema must still start old code: %v", err)
	}
}
