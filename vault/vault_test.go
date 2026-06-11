package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestVault writes an ed25519 SSH key pair to a temp directory and
// initializes a vault there, returning the vault directory and store.
func newTestVault(t *testing.T) (string, *Store) {
	t.Helper()
	base := t.TempDir()
	kp := testEd25519Key(t)
	pubPath := filepath.Join(base, "id_ed25519.pub")
	privPath := filepath.Join(base, "id_ed25519")
	if err := os.WriteFile(pubPath, kp.public, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privPath, kp.private, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "vault")
	s, err := Init(dir, pubPath, privPath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return dir, s
}

func TestInitOpenLoadEmpty(t *testing.T) {
	dir, _ := newTestVault(t)

	// Files and permissions. POSIX modes do not map onto Windows
	// (os.Stat reports 0777/0666 there), so only assert them elsewhere.
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(dir); err != nil {
			t.Fatal(err)
		} else if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("vault dir mode = %o, want 700", got)
		}
		for _, f := range []struct {
			name string
			perm os.FileMode
		}{
			{configFile, 0o600},
			{dbFile, 0o600},
		} {
			info, err := os.Stat(filepath.Join(dir, f.name))
			if err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
			if got := info.Mode().Perm(); got != f.perm {
				t.Errorf("%s mode = %o, want %o", f.name, got, f.perm)
			}
		}
	} else {
		for _, name := range []string{configFile, dbFile} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	db, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if db.Version != 1 {
		t.Errorf("Version = %d, want 1", db.Version)
	}
	if len(db.Entries) != 0 {
		t.Errorf("new vault has %d entries, want 0", len(db.Entries))
	}
}

func TestInitTwiceFails(t *testing.T) {
	dir, s := newTestVault(t)
	if _, err := Init(dir, s.Config.Recipient, s.Config.Identity); err == nil {
		t.Fatal("second Init succeeded, want error")
	}
}

func TestInitBadKeys(t *testing.T) {
	base := t.TempDir()
	kp := testEd25519Key(t)
	pubPath := filepath.Join(base, "id.pub")
	privPath := filepath.Join(base, "id")
	if err := os.WriteFile(pubPath, kp.public, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privPath, kp.private, 0o600); err != nil {
		t.Fatal(err)
	}
	badPub := filepath.Join(base, "bad.pub")
	if err := os.WriteFile(badPub, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		recipient string
		identity  string
	}{
		{"missing recipient", filepath.Join(base, "nope.pub"), privPath},
		{"invalid recipient", badPub, privPath},
		{"missing identity", pubPath, filepath.Join(base, "nope")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(base, "vault-"+strings.ReplaceAll(tt.name, " ", "-"))
			if _, err := Init(dir, tt.recipient, tt.identity); err == nil {
				t.Fatal("Init succeeded, want error")
			}
		})
	}
}

func TestOpenUninitialized(t *testing.T) {
	_, err := Open(t.TempDir())
	if err == nil {
		t.Fatal("Open of empty dir succeeded, want error")
	}
	if !strings.Contains(err.Error(), "hal-vault init") {
		t.Errorf("error %q does not point to \"hal-vault init\"", err)
	}
}

func TestAddAssignsIDAndDefaults(t *testing.T) {
	db := &DB{Version: 1}
	if err := db.Add(Entry{Label: "my api", Value: "v"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	e := db.Entries[0]
	if len(e.ID) != idLength {
		t.Errorf("ID %q has length %d, want %d", e.ID, len(e.ID), idLength)
	}
	for _, c := range e.ID {
		if !strings.ContainsRune(idAlphabet, c) {
			t.Errorf("ID %q contains %q, not in alphabet", e.ID, c)
		}
	}
	if e.Type != "other" {
		t.Errorf("Type = %q, want default \"other\"", e.Type)
	}
	if e.CreatedAt.IsZero() || e.UpdatedAt.IsZero() {
		t.Error("timestamps were not assigned")
	}
}

func TestAddValidation(t *testing.T) {
	tests := []struct {
		name  string
		setup func(db *DB)
		entry Entry
	}{
		{"empty label", nil, Entry{Value: "v"}},
		{"invalid type", nil, Entry{Label: "x", Type: "nonsense"}},
		{
			"duplicate explicit ID",
			func(db *DB) {
				if err := db.Add(Entry{ID: "abc123", Label: "first"}); err != nil {
					t.Fatal(err)
				}
			},
			Entry{ID: "abc123", Label: "second"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &DB{Version: 1}
			if tt.setup != nil {
				tt.setup(db)
			}
			if err := db.Add(tt.entry); err == nil {
				t.Fatal("Add succeeded, want error")
			}
		})
	}
}

func TestAddAcceptsAllValidTypes(t *testing.T) {
	db := &DB{Version: 1}
	for _, typ := range EntryTypes {
		if err := db.Add(Entry{Label: "l-" + typ, Type: typ}); err != nil {
			t.Errorf("Add with type %q: %v", typ, err)
		}
	}
}

func TestGet(t *testing.T) {
	db := &DB{Version: 1}
	if err := db.Add(Entry{ID: "aaa111", Label: "GitHub Token", Value: "gh-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{ID: "bbb222", Label: "AWS Key", Value: "aws-secret"}); err != nil {
		t.Fatal(err)
	}

	t.Run("by ID", func(t *testing.T) {
		e, err := db.Get("aaa111")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if e.Label != "GitHub Token" {
			t.Errorf("got entry %q, want \"GitHub Token\"", e.Label)
		}
	})

	t.Run("by label case-insensitive", func(t *testing.T) {
		for _, q := range []string{"GitHub Token", "github token", "GITHUB TOKEN"} {
			e, err := db.Get(q)
			if err != nil {
				t.Fatalf("Get(%q): %v", q, err)
			}
			if e.ID != "aaa111" {
				t.Errorf("Get(%q) returned %q, want aaa111", q, e.ID)
			}
		}
	})

	t.Run("ID match wins over label", func(t *testing.T) {
		// An entry whose label equals another entry's ID.
		if err := db.Add(Entry{ID: "ccc333", Label: "aaa111", Value: "decoy"}); err != nil {
			t.Fatal(err)
		}
		e, err := db.Get("aaa111")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if e.ID != "aaa111" {
			t.Errorf("Get returned %q, want exact ID match aaa111", e.ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		if _, err := db.Get("does-not-exist"); err == nil {
			t.Fatal("Get of missing entry succeeded, want error")
		}
	})
}

func TestGetAmbiguousLabel(t *testing.T) {
	db := &DB{Version: 1}
	if err := db.Add(Entry{ID: "dup001", Label: "Shared Label", Value: "TOPSECRET-A"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{ID: "dup002", Label: "shared label", Value: "TOPSECRET-B"}); err != nil {
		t.Fatal(err)
	}
	_, err := db.Get("SHARED LABEL")
	if err == nil {
		t.Fatal("Get with ambiguous label succeeded, want error")
	}
	msg := err.Error()
	for _, id := range []string{"dup001", "dup002"} {
		if !strings.Contains(msg, id) {
			t.Errorf("ambiguous error %q does not list candidate %s", msg, id)
		}
	}
	for _, val := range []string{"TOPSECRET-A", "TOPSECRET-B"} {
		if strings.Contains(msg, val) {
			t.Errorf("ambiguous error %q leaks secret value %q", msg, val)
		}
	}
}

func TestRemove(t *testing.T) {
	db := &DB{Version: 1}
	if err := db.Add(Entry{ID: "rm0001", Label: "doomed"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{ID: "rm0002", Label: "survivor"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Remove("rm0001"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(db.Entries) != 1 || db.Entries[0].ID != "rm0002" {
		t.Errorf("after Remove, entries = %v, want only rm0002", db.Entries)
	}
	if err := db.Remove("rm0001"); err == nil {
		t.Fatal("second Remove succeeded, want error")
	}
}

func TestPersistenceAcrossStores(t *testing.T) {
	dir, s := newTestVault(t)
	db, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{Label: "GitHub Token", Value: "ghp_secret123456", Type: "token", Tags: []string{"work"}, Note: "ci"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{Label: "密码", Value: "ünïcode-välue"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(db); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Open a brand-new Store instance and verify everything roundtripped.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	db2, err := s2.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(db2.Entries) != 2 {
		t.Fatalf("reloaded vault has %d entries, want 2", len(db2.Entries))
	}
	e, err := db2.Get("github token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if e.Value != "ghp_secret123456" || e.Type != "token" || e.Note != "ci" ||
		len(e.Tags) != 1 || e.Tags[0] != "work" {
		t.Errorf("entry did not roundtrip: %+v", e)
	}
	u, err := db2.Get("密码")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if u.Value != "ünïcode-välue" {
		t.Errorf("unicode value did not roundtrip: %q", u.Value)
	}
}

func TestUpdateViaGetPersists(t *testing.T) {
	dir, s := newTestVault(t)
	db, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{Label: "rotateme", Value: "old-value"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(db); err != nil {
		t.Fatal(err)
	}

	// Get returns a pointer into the DB: mutate, bump UpdatedAt, save.
	e, err := db.Get("rotateme")
	if err != nil {
		t.Fatal(err)
	}
	e.Value = "new-value"
	e.Tags = []string{"rotated"}
	e.UpdatedAt = time.Now().UTC().Add(time.Hour)
	if err := s.Save(db); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db2, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	got, err := db2.Get("rotateme")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "new-value" {
		t.Errorf("Value = %q, want \"new-value\"", got.Value)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "rotated" {
		t.Errorf("Tags = %v, want [rotated]", got.Tags)
	}
	if !got.UpdatedAt.After(got.CreatedAt) {
		t.Error("UpdatedAt was not persisted ahead of CreatedAt")
	}
}

func TestSaveKeepsBackupGeneration(t *testing.T) {
	dir, s := newTestVault(t) // generation 0: empty DB
	db, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{ID: "gen001", Label: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(db); err != nil { // generation 1; .bak = generation 0
		t.Fatal(err)
	}
	if err := db.Add(Entry{ID: "gen002", Label: "second"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(db); err != nil { // generation 2; .bak = generation 1
		t.Fatal(err)
	}

	// Decrypt the backup by hand: it must hold exactly generation 1.
	bak, err := os.ReadFile(filepath.Join(dir, dbBakFile))
	if err != nil {
		t.Fatalf("reading %s: %v", dbBakFile, err)
	}
	key, err := os.ReadFile(s.Config.Identity)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseIdentity(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Decrypt(id, bak)
	if err != nil {
		t.Fatalf("decrypting backup: %v", err)
	}
	if !strings.Contains(string(plaintext), "gen001") || strings.Contains(string(plaintext), "gen002") {
		t.Errorf("backup is not the previous generation: %s", plaintext)
	}

	// The current DB must hold generation 2.
	db2, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(db2.Entries) != 2 {
		t.Errorf("current DB has %d entries, want 2", len(db2.Entries))
	}

	// No stray temp files left behind.
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{configFile: true, dbFile: true, dbBakFile: true}
	for _, f := range files {
		if !want[f.Name()] {
			t.Errorf("unexpected file in vault dir: %s", f.Name())
		}
	}
}

func TestLoadCorruptedDB(t *testing.T) {
	dir, s := newTestVault(t)
	if err := os.WriteFile(filepath.Join(dir, dbFile), []byte("corrupted garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("Load of corrupted DB succeeded, want error")
	}
}

func TestLoadMissingIdentityFile(t *testing.T) {
	_, s := newTestVault(t)
	s.Config.Identity = filepath.Join(t.TempDir(), "gone")
	if _, err := s.Load(); err == nil {
		t.Fatal("Load with missing identity succeeded, want error")
	}
}

func TestNewIDUniquenessAndFormat(t *testing.T) {
	existing := make(map[string]bool)
	for i := 0; i < 2000; i++ {
		id, err := NewID(existing)
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if len(id) != idLength {
			t.Fatalf("ID %q has length %d, want %d", id, len(id), idLength)
		}
		for _, c := range id {
			if !strings.ContainsRune(idAlphabet, c) {
				t.Fatalf("ID %q contains %q, not in Crockford alphabet", id, c)
			}
		}
		if existing[id] {
			t.Fatalf("NewID returned duplicate %q", id)
		}
		existing[id] = true
	}
}

func TestValidType(t *testing.T) {
	for _, typ := range EntryTypes {
		if !ValidType(typ) {
			t.Errorf("ValidType(%q) = false, want true", typ)
		}
	}
	for _, typ := range []string{"", "API_KEY", "passwd", "unknown"} {
		if ValidType(typ) {
			t.Errorf("ValidType(%q) = true, want false", typ)
		}
	}
}

func searchTestDB(t *testing.T) *DB {
	t.Helper()
	db := &DB{Version: 1}
	entries := []Entry{
		{ID: "src001", Label: "GitHub Token", Type: "token", Tags: []string{"work", "git"}, Note: "personal access token"},
		{ID: "src002", Label: "AWS Key", Type: "api_key", Tags: []string{"work", "cloud"}, Note: "prod account"},
		{ID: "src003", Label: "Email Password", Type: "password", Tags: []string{"personal"}},
		{ID: "src004", Label: "Server Cert", Type: "cert", Tags: []string{"cloud"}, Note: "TLS for api.example.com"},
	}
	for _, e := range entries {
		if err := db.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestSearch(t *testing.T) {
	db := searchTestDB(t)
	tests := []struct {
		name    string
		query   string
		tag     string
		typ     string
		wantIDs []string
	}{
		{"all empty matches everything", "", "", "", []string{"src001", "src002", "src003", "src004"}},
		{"query label", "github", "", "", []string{"src001"}},
		{"query is case-insensitive", "GITHUB", "", "", []string{"src001"}},
		{"query matches note", "prod", "", "", []string{"src002"}},
		{"query substring across fields", "wor", "", "", []string{"src001", "src002", "src003"}}, // tags "work" + label "Password"
		{"query matches type", "api", "", "", []string{"src002", "src004"}},                      // api_key type + api.example.com note
		{"query no match", "zzz", "", "", nil},
		{"tag exact", "", "work", "", []string{"src001", "src002"}},
		{"tag is exact not substring", "", "wor", "", nil},
		{"type exact", "", "", "password", []string{"src003"}},
		{"type is exact not substring", "", "", "pass", nil},
		{"query AND tag", "key", "cloud", "", []string{"src002"}},
		{"query AND type", "work", "", "token", []string{"src001"}},
		{"tag AND type", "", "cloud", "cert", []string{"src004"}},
		{"query AND tag AND type", "prod", "work", "api_key", []string{"src002"}},
		{"AND filters can exclude everything", "github", "", "password", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.Search(tt.query, tt.tag, tt.typ)
			var gotIDs []string
			for _, e := range got {
				gotIDs = append(gotIDs, e.ID)
			}
			if len(gotIDs) != len(tt.wantIDs) {
				t.Fatalf("Search(%q, %q, %q) = %v, want %v", tt.query, tt.tag, tt.typ, gotIDs, tt.wantIDs)
			}
			for i := range tt.wantIDs {
				if gotIDs[i] != tt.wantIDs[i] {
					t.Fatalf("Search(%q, %q, %q) = %v, want %v", tt.query, tt.tag, tt.typ, gotIDs, tt.wantIDs)
				}
			}
		})
	}
}

func TestAddRejectsInvalidUTF8(t *testing.T) {
	db := &DB{Version: SchemaVersion}
	err := db.Add(Entry{Label: "binary", Value: "pre\xff\xfepost"})
	if err == nil {
		t.Fatal("Add accepted an invalid UTF-8 value; it would be corrupted by JSON serialization")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error %q should mention UTF-8", err)
	}
}

func TestLoadRejectsNewerVersion(t *testing.T) {
	dir, s := newTestVault(t)

	// Hand-craft a version-2 database and store it through the same
	// encryption path Save uses.
	pub, err := os.ReadFile(s.Config.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRecipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := Encrypt(r, []byte(`{"version":2,"entries":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, dbFile), ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("Load accepted a database from a newer format version")
	}

	// Version 0 (missing) is malformed.
	ciphertext, err = Encrypt(r, []byte(`{"entries":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, dbFile), ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("Load accepted a database without a version")
	}
}

func TestFailedInitLeavesNoState(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "vault")
	badPub := filepath.Join(base, "garbage.pub")
	if err := os.WriteFile(badPub, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(dir, badPub, badPub); err == nil {
		t.Fatal("Init succeeded with a garbage recipient")
	}
	if _, err := os.Stat(filepath.Join(dir, configFile)); !os.IsNotExist(err) {
		t.Error("failed Init left config.json behind, blocking retry")
	}

	// And a retry with good keys must succeed.
	kp := testEd25519Key(t)
	pubPath := filepath.Join(base, "id_ed25519.pub")
	privPath := filepath.Join(base, "id_ed25519")
	if err := os.WriteFile(pubPath, kp.public, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privPath, kp.private, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(dir, pubPath, privPath); err != nil {
		t.Fatalf("Init retry after failure: %v", err)
	}
}

func TestSaveKeepsLiveDBPresent(t *testing.T) {
	dir, s := newTestVault(t)
	db, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Entry{Label: "a", Value: "value-1234567890"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(db); err != nil {
		t.Fatal(err)
	}
	// After the backup rotation, both generations must exist: the hard-link
	// (or copy) scheme never removes the live secrets.db.
	for _, name := range []string{dbFile, dbBakFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing after second save: %v", name, err)
		}
	}
}

func TestUpdateConcurrentWritesAreNotLost(t *testing.T) {
	_, s := newTestVault(t)

	const writers = 8
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Update(func(db *DB) error {
				return db.Add(Entry{
					Label: fmt.Sprintf("entry-%d", i),
					Value: "concurrent-value-123456",
				})
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}

	db, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Entries) != writers {
		t.Fatalf("after %d concurrent Updates the vault has %d entries; writes were lost",
			writers, len(db.Entries))
	}
}
