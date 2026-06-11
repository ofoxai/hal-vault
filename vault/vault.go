// Package vault implements a small encrypted secret store. The whole
// database is kept as a single age-encrypted blob, encrypted to an SSH
// public key and decrypted with the matching SSH private key.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	configFile = "config.json"
	dbFile     = "secrets.db"
	dbBakFile  = "secrets.db.bak"
	lockFile   = ".lock"
)

// SchemaVersion is the database format version this package reads and writes.
const SchemaVersion = 1

// DefaultDir returns the default vault directory: $HAL_VAULT_DIR if set,
// otherwise ~/.hal-vault.
func DefaultDir() string {
	if dir := os.Getenv("HAL_VAULT_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hal-vault"
	}
	return filepath.Join(home, ".hal-vault")
}

// Config points the vault at the SSH key pair used for encryption.
type Config struct {
	// Recipient is the path to the SSH public key (encryption).
	Recipient string `json:"recipient"`
	// Identity is the path to the SSH private key (decryption).
	Identity string `json:"identity"`
}

// Store is an opened vault directory.
type Store struct {
	Dir    string
	Config Config

	// PassphrasePrompt is invoked when the SSH private key is
	// passphrase-protected. If nil, decrypting with such a key fails.
	PassphrasePrompt func() ([]byte, error)
}

// DB is the decrypted database held inside secrets.db.
type DB struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Init creates a new vault in dir, bound to the given SSH key pair, and
// writes an encrypted empty database. It fails if the vault is already
// initialized (config.json exists). Only the recipient (public key) is
// needed to create the database.
func Init(dir, recipientPath, identityPath string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	// Validate the keys before creating any state, so a failed Init leaves
	// nothing behind. Encryption of the empty DB needs the recipient.
	pub, err := os.ReadFile(recipientPath)
	if err != nil {
		return nil, fmt.Errorf("reading recipient: %w", err)
	}
	if _, err := ParseRecipient(pub); err != nil {
		return nil, fmt.Errorf("invalid recipient %s: %w", recipientPath, err)
	}
	// The identity may be passphrase-protected, so only check it exists.
	if _, err := os.Stat(identityPath); err != nil {
		return nil, fmt.Errorf("identity not accessible: %w", err)
	}

	s := &Store{
		Dir:    dir,
		Config: Config{Recipient: recipientPath, Identity: identityPath},
	}
	cfg, err := json.MarshalIndent(s.Config, "", "  ")
	if err != nil {
		return nil, err
	}
	// O_EXCL makes the already-initialized check atomic: two concurrent
	// Inits cannot both succeed.
	configPath := filepath.Join(dir, configFile)
	f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("vault already initialized: %s exists", configPath)
		}
		return nil, err
	}
	_, werr := f.Write(append(cfg, '\n'))
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(configPath)
		return nil, err
	}
	if err := s.Save(&DB{Version: SchemaVersion, Entries: []Entry{}}); err != nil {
		// Leave no half-initialized vault behind, so Init can be retried.
		os.Remove(configPath)
		return nil, err
	}
	return s, nil
}

// Open opens an existing vault in dir.
func Open(dir string) (*Store, error) {
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no vault at %s — run \"hal-vault init\" to bring one online", dir)
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("malformed %s: %w", configFile, err)
	}
	return &Store{Dir: dir, Config: cfg}, nil
}

// Load decrypts and parses the database.
func (s *Store) Load() (*DB, error) {
	key, err := os.ReadFile(s.Config.Identity)
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	id, err := ParseIdentity(key, s.PassphrasePrompt)
	if err != nil {
		return nil, fmt.Errorf("parsing identity %s: %w", s.Config.Identity, err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(s.Dir, dbFile))
	if err != nil {
		return nil, err
	}
	plaintext, err := Decrypt(id, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypting vault: %w", err)
	}
	var db DB
	if err := json.Unmarshal(plaintext, &db); err != nil {
		return nil, fmt.Errorf("malformed vault database: %w", err)
	}
	if db.Version < 1 {
		return nil, errors.New("malformed vault database: missing version")
	}
	if db.Version > SchemaVersion {
		return nil, fmt.Errorf("vault database version %d is newer than this hal-vault supports (%d); upgrade hal-vault",
			db.Version, SchemaVersion)
	}
	return &db, nil
}

// Update locks the vault, loads the database, applies fn, and saves the
// result. The exclusive lock covers the whole read-modify-write cycle, so
// concurrent hal-vault processes cannot lose each other's writes. Mutating
// callers should prefer Update over a bare Load/Save pair.
func (s *Store) Update(fn func(*DB) error) error {
	unlock, err := lockDir(s.Dir)
	if err != nil {
		return fmt.Errorf("locking vault: %w", err)
	}
	defer unlock()
	db, err := s.Load()
	if err != nil {
		return err
	}
	if err := fn(db); err != nil {
		return err
	}
	return s.Save(db)
}

// Save encrypts and writes the database atomically: the new database is
// written and fsynced to a temporary file, the previous database is kept as
// secrets.db.bak, and the temporary file replaces secrets.db in a single
// rename — so a complete secrets.db exists at every instant, even across
// crashes.
func (s *Store) Save(db *DB) error {
	pub, err := os.ReadFile(s.Config.Recipient)
	if err != nil {
		return fmt.Errorf("reading recipient: %w", err)
	}
	r, err := ParseRecipient(pub)
	if err != nil {
		return fmt.Errorf("parsing recipient %s: %w", s.Config.Recipient, err)
	}
	plaintext, err := json.Marshal(db)
	if err != nil {
		return err
	}
	ciphertext, err := Encrypt(r, plaintext)
	if err != nil {
		return fmt.Errorf("encrypting vault: %w", err)
	}

	tmp, err := os.CreateTemp(s.Dir, dbFile+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		tmp.Close()
		return err
	}
	// Flush to stable storage before the rename, so a power failure cannot
	// persist the rename without the data.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Keep the previous generation as secrets.db.bak via a hard link (or a
	// copy where links are unsupported). The live secrets.db stays in place
	// and is only ever replaced by the single atomic rename below.
	dbPath := filepath.Join(s.Dir, dbFile)
	bakPath := filepath.Join(s.Dir, dbBakFile)
	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Remove(bakPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Link(dbPath, bakPath); err != nil {
			cur, rerr := os.ReadFile(dbPath)
			if rerr != nil {
				return rerr
			}
			if werr := os.WriteFile(bakPath, cur, 0o600); werr != nil {
				return werr
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmpName, dbPath); err != nil {
		return err
	}
	syncDir(s.Dir)
	return nil
}

// syncDir flushes directory metadata so a completed Save survives power
// loss. Best-effort: directory fsync is not supported on all platforms
// (e.g. Windows), and the data itself is already synced.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	d.Sync()
}

// Get returns the entry matching idOrLabel. An exact ID match wins; otherwise
// a case-insensitive exact label match is tried. If several entries share the
// label, an error listing the candidate IDs and labels (never values) is
// returned.
func (db *DB) Get(idOrLabel string) (*Entry, error) {
	for i := range db.Entries {
		if db.Entries[i].ID == idOrLabel {
			return &db.Entries[i], nil
		}
	}
	var matches []*Entry
	for i := range db.Entries {
		if strings.EqualFold(db.Entries[i].Label, idOrLabel) {
			matches = append(matches, &db.Entries[i])
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no entry found for %q", idOrLabel)
	case 1:
		return matches[0], nil
	default:
		var candidates []string
		for _, e := range matches {
			candidates = append(candidates, fmt.Sprintf("%s (%s)", e.ID, e.Label))
		}
		return nil, fmt.Errorf("label %q is ambiguous, use an ID: %s",
			idOrLabel, strings.Join(candidates, ", "))
	}
}

// Add appends e to the database, assigning an ID and timestamps if empty.
// An empty Type defaults to "other"; invalid types are rejected.
func (db *DB) Add(e Entry) error {
	if e.Label == "" {
		return errors.New("entry label must not be empty")
	}
	// JSON serialization coerces invalid UTF-8 to U+FFFD, which would
	// silently corrupt the stored secret. Reject it up front instead.
	if !utf8.ValidString(e.Value) {
		return errors.New("secret value is not valid UTF-8; encode binary secrets (e.g. with base64) before storing")
	}
	if e.Type == "" {
		e.Type = "other"
	}
	if !ValidType(e.Type) {
		return fmt.Errorf("invalid type %q (valid: %s)", e.Type, strings.Join(EntryTypes, ", "))
	}
	existing := make(map[string]bool, len(db.Entries))
	for i := range db.Entries {
		existing[db.Entries[i].ID] = true
	}
	if e.ID == "" {
		id, err := NewID(existing)
		if err != nil {
			return err
		}
		e.ID = id
	} else if existing[e.ID] {
		return fmt.Errorf("duplicate entry ID %q", e.ID)
	}
	now := time.Now().UTC()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	if e.UpdatedAt.IsZero() {
		e.UpdatedAt = now
	}
	db.Entries = append(db.Entries, e)
	return nil
}

// Remove deletes the entry with the given ID.
func (db *DB) Remove(id string) error {
	for i := range db.Entries {
		if db.Entries[i].ID == id {
			db.Entries = append(db.Entries[:i], db.Entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no entry found for ID %q", id)
}

// Search returns the entries matching all given filters. query is a
// case-insensitive substring match over label, note, tags and type; tag is an
// exact tag filter; typ is an exact type filter. Empty filters match all.
func (db *DB) Search(query, tag, typ string) []Entry {
	q := strings.ToLower(query)
	var out []Entry
	for _, e := range db.Entries {
		if typ != "" && e.Type != typ {
			continue
		}
		if tag != "" && !containsString(e.Tags, tag) {
			continue
		}
		if q != "" && !matchesQuery(&e, q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// matchesQuery reports whether the lowercase query q is a substring of the
// entry's label, note, type or any tag.
func matchesQuery(e *Entry, q string) bool {
	if strings.Contains(strings.ToLower(e.Label), q) ||
		strings.Contains(strings.ToLower(e.Note), q) ||
		strings.Contains(strings.ToLower(e.Type), q) {
		return true
	}
	for _, t := range e.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
