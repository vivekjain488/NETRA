package store

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/netra/backend/migrations"
)

func TestLoadMigrationsOrdersByVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"0010_later.sql":  {Data: []byte("SELECT 10;")},
		"0002_second.sql": {Data: []byte("SELECT 2;")},
		"0001_init.sql":   {Data: []byte("SELECT 1;")},
	}

	got, err := LoadMigrations(fsys)
	if err != nil {
		t.Fatalf("LoadMigrations returned error: %v", err)
	}
	want := []int{1, 2, 10}
	if len(got) != len(want) {
		t.Fatalf("got %d migrations, want %d", len(got), len(want))
	}
	for i, v := range want {
		if got[i].Version != v {
			// Lexical ordering would place 0010 before 0002 for wider ranges;
			// migrations must apply in numeric order.
			t.Errorf("migration %d has version %d, want %d", i, got[i].Version, v)
		}
	}
	if got[0].Name != "init" {
		t.Errorf("name = %q, want init", got[0].Name)
	}
}

func TestLoadMigrationsRejectsDuplicateVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_init.sql":  {Data: []byte("SELECT 1;")},
		"0001_other.sql": {Data: []byte("SELECT 2;")},
	}

	if _, err := LoadMigrations(fsys); err == nil {
		t.Fatal("duplicate versions accepted; apply order would be undefined")
	}
}

func TestLoadMigrationsRejectsBadFilenames(t *testing.T) {
	for _, name := range []string{"init.sql", "abc_init.sql"} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadMigrations(fstest.MapFS{name: {Data: []byte("SELECT 1;")}}); err == nil {
				t.Errorf("filename %q accepted, want error", name)
			}
		})
	}
}

func TestEmbeddedMigrationsAreValid(t *testing.T) {
	got, err := LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatalf("embedded migrations are invalid: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no migrations were embedded; the schema would never be created")
	}
	if got[0].Version != 1 {
		t.Errorf("first migration version = %d, want 1", got[0].Version)
	}
	if !strings.Contains(got[0].SQL, "CREATE TABLE users") {
		t.Error("initial migration does not create the users table")
	}
}
