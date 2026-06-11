package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/ofoxai/hal-vault/vault"
)

func cmdInit(args []string, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "init", "init [-r PUBKEY] [-i PRIVKEY] [-d DIR]")
	rPath := fs.String("r", "", "SSH public key path")
	iPath := fs.String("i", "", "SSH private key path")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageErrorf("init takes no arguments")
	}
	recipient, identity, generated, err := resolveKeyPair(*rPath, *iPath)
	if err != nil {
		return err
	}
	if _, err := vault.Init(*dir, recipient, identity); err != nil {
		return err
	}
	if generated {
		fmt.Fprintf(stdout, "generated SSH key pair: %s\n", identity)
	}
	fmt.Fprintf(stdout, "initialized vault in %s\n", *dir)
	fmt.Fprintf(stdout, "recipient: %s\n", recipient)
	fmt.Fprintf(stdout, "identity:  %s\n", identity)
	fmt.Fprintln(stdout, "hal-vault is fully operational.")
	return nil
}

func cmdAdd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "add", "add LABEL [-t TYPE] [--tags TAG,...] [-n NOTE] [-d DIR]")
	typ := fs.String("t", "", "entry type")
	tags := fs.String("tags", "", "comma-separated tags")
	note := fs.String("n", "", "note")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("add takes exactly one LABEL argument")
	}
	if *typ != "" && !vault.ValidType(*typ) {
		return usageErrorf("invalid type %q (valid: %s)", *typ, strings.Join(vault.EntryTypes, ", "))
	}

	s, err := openStore(*dir, stdin, stderr)
	if err != nil {
		return err
	}
	// Read the secret before taking the vault lock: the interactive prompt
	// can block indefinitely and must not hold up other processes.
	value, err := readSecret(stdin, stderr)
	if err != nil {
		return err
	}
	var added vault.Entry
	err = s.Update(func(db *vault.DB) error {
		if err := db.Add(vault.Entry{
			Label: pos[0],
			Value: value,
			Type:  *typ,
			Tags:  splitTags(*tags),
			Note:  *note,
		}); err != nil {
			return err
		}
		added = db.Entries[len(db.Entries)-1]
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "added %s %s: %s\n", added.ID, added.Label, added.Masked())
	return nil
}

func cmdGet(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "get", "get ID|LABEL [--reveal] [--json] [-d DIR]")
	reveal := fs.Bool("reveal", false, "print the raw secret value")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("get takes exactly one ID|LABEL argument")
	}

	s, err := openStore(*dir, stdin, stderr)
	if err != nil {
		return err
	}
	db, err := s.Load()
	if err != nil {
		return err
	}
	e, err := db.Get(pos[0])
	if err != nil {
		return err
	}
	switch {
	case *asJSON:
		return writeJSON(stdout, entryToJSON(e, *reveal))
	case *reveal:
		// Raw value plus a single newline, nothing else, so that
		// KEY=$(hal-vault get x --reveal) works.
		fmt.Fprintf(stdout, "%s\n", e.Value)
		return nil
	default:
		printEntry(stdout, e)
		return nil
	}
}

func cmdList(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "list", "list [--json] [-d DIR]")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageErrorf("list takes no arguments")
	}

	s, err := openStore(*dir, stdin, stderr)
	if err != nil {
		return err
	}
	db, err := s.Load()
	if err != nil {
		return err
	}
	return renderEntries(stdout, db.Entries, *asJSON)
}

func cmdSearch(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "search", "search [QUERY] [--tag TAG] [--type TYPE] [--json] [-d DIR]")
	tag := fs.String("tag", "", "exact tag filter")
	typ := fs.String("type", "", "exact type filter")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usageErrorf("search takes at most one QUERY argument")
	}
	query := ""
	if len(pos) == 1 {
		query = pos[0]
	}
	if query == "" && *tag == "" && *typ == "" {
		return usageErrorf("search needs a QUERY, --tag or --type")
	}
	if *typ != "" && !vault.ValidType(*typ) {
		return usageErrorf("invalid type %q (valid: %s)", *typ, strings.Join(vault.EntryTypes, ", "))
	}

	s, err := openStore(*dir, stdin, stderr)
	if err != nil {
		return err
	}
	db, err := s.Load()
	if err != nil {
		return err
	}
	return renderEntries(stdout, db.Search(query, *tag, *typ), *asJSON)
}

func cmdUpdate(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "update",
		"update ID|LABEL [--label LABEL] [-t TYPE] [--tags TAG,...] [-n NOTE] [--value] [-d DIR]")
	label := fs.String("label", "", "new label")
	typ := fs.String("t", "", "new entry type")
	tags := fs.String("tags", "", "new comma-separated tags (replaces all tags)")
	note := fs.String("n", "", "new note")
	value := fs.Bool("value", false, "read a new secret value from stdin or prompt")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("update takes exactly one ID|LABEL argument")
	}
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if !set["label"] && !set["t"] && !set["tags"] && !set["n"] && !*value {
		return usageErrorf("nothing to update: give --label, -t, --tags, -n or --value")
	}
	if set["label"] && *label == "" {
		return usageErrorf("label must not be empty")
	}
	if set["t"] && !vault.ValidType(*typ) {
		return usageErrorf("invalid type %q (valid: %s)", *typ, strings.Join(vault.EntryTypes, ", "))
	}

	s, err := openStore(*dir, stdin, stderr)
	if err != nil {
		return err
	}
	// Read the secret before taking the vault lock: the interactive prompt
	// can block indefinitely and must not hold up other processes.
	var newValue string
	if *value {
		v, err := readSecret(stdin, stderr)
		if err != nil {
			return err
		}
		newValue = v
	}
	var updated vault.Entry
	err = s.Update(func(db *vault.DB) error {
		e, err := db.Get(pos[0])
		if err != nil {
			return err
		}
		if set["label"] {
			e.Label = *label
		}
		if set["t"] {
			e.Type = *typ
		}
		if set["tags"] {
			e.Tags = splitTags(*tags)
		}
		if set["n"] {
			e.Note = *note
		}
		if *value {
			e.Value = newValue
		}
		e.UpdatedAt = time.Now().UTC()
		updated = *e
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "updated %s %s: %s\n", updated.ID, updated.Label, updated.Masked())
	return nil
}

func cmdRm(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "rm", "rm ID|LABEL [-f] [-d DIR]")
	force := fs.Bool("f", false, "skip confirmation")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("rm takes exactly one ID|LABEL argument")
	}

	s, err := openStore(*dir, stdin, stderr)
	if err != nil {
		return err
	}
	// Resolve and confirm outside the vault lock: the [y/N] prompt can
	// block indefinitely. The removal below re-resolves by ID under the
	// lock, so a concurrent change cannot remove the wrong entry.
	db, err := s.Load()
	if err != nil {
		return err
	}
	e, err := db.Get(pos[0])
	if err != nil {
		return err
	}
	if !*force {
		if !isTerminal(stdin) {
			return errors.New("I'm sorry, I can't remove entries without -f when no one is at the terminal")
		}
		fmt.Fprintf(stderr, "remove %s (%s)? [y/N] ", e.ID, e.Label)
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
		default:
			return errors.New("understood — nothing was removed")
		}
	}
	id, label, masked := e.ID, e.Label, e.Masked()
	if err := s.Update(func(db *vault.DB) error {
		return db.Remove(id)
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "removed %s %s: %s\n", id, label, masked)
	return nil
}

// newFlagSet creates a flag set with the common -d flag and a terse
// single-line usage message.
func newFlagSet(stderr io.Writer, name, usageLine string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: hal-vault %s\n", usageLine)
	}
	dir := fs.String("d", vault.DefaultDir(), "vault directory")
	return fs, dir
}

// parseFlags parses args, allowing flags and positional arguments to be
// interleaved (the standard flag package alone stops at the first
// non-flag argument). It returns the positional arguments.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, flag.ErrHelp
			}
			return nil, errFlagParse
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// openStore opens the vault and wires up the interactive passphrase prompt
// for passphrase-protected SSH keys.
func openStore(dir string, stdin io.Reader, stderr io.Writer) (*vault.Store, error) {
	s, err := vault.Open(dir)
	if err != nil {
		return nil, err
	}
	s.PassphrasePrompt = passphrasePrompt(stdin, stderr)
	return s, nil
}

// isTerminal reports whether r is an interactive terminal.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// readSecret obtains a secret value. When stdin is a terminal it asks twice
// with hidden input; otherwise it reads all of stdin and strips one trailing
// newline. The value never appears on the command line. Binary (non-UTF-8)
// input is rejected: it would be silently corrupted by JSON serialization.
func readSecret(stdin io.Reader, stderr io.Writer) (string, error) {
	v, err := readSecretRaw(stdin, stderr)
	if err != nil {
		return "", err
	}
	if !utf8.ValidString(v) {
		return "", errors.New("I'm afraid I can't store that: the value is not valid UTF-8 (base64-encode binary secrets first)")
	}
	return v, nil
}

func readSecretRaw(stdin io.Reader, stderr io.Writer) (string, error) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		fmt.Fprint(stderr, "Enter secret value: ")
		first, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(stderr, "Confirm secret value: ")
		second, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", errors.New("those values do not match; nothing was stored")
		}
		return string(first), nil
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(string(data), "\n")
	return strings.TrimSuffix(s, "\r"), nil
}

// passphrasePrompt returns a hidden prompt for passphrase-protected SSH
// keys. It reads from stdin when it is a terminal, falling back to the
// controlling terminal so that piped commands still work. Without any
// terminal it fails cleanly.
func passphrasePrompt(stdin io.Reader, stderr io.Writer) func() ([]byte, error) {
	return func() ([]byte, error) {
		device := "/dev/tty"
		if runtime.GOOS == "windows" {
			device = "CONIN$" // the Windows console input device
		}
		fd := -1
		if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			fd = int(f.Fd())
		} else if tty, err := os.Open(device); err == nil {
			defer tty.Close()
			fd = int(tty.Fd())
		}
		if fd < 0 {
			return nil, errors.New("the SSH key is passphrase-protected and there is no terminal to ask at")
		}
		fmt.Fprint(stderr, "Enter passphrase for SSH key: ")
		pass, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		return pass, err
	}
}

// defaultKeyName is the dedicated hal-vault SSH key in ~/.ssh. It is named
// after hal-vault and kept separate from the user's day-to-day SSH keys, so
// rotating or replacing those never locks the vault.
const defaultKeyName = "hal-vault_ed25519"

// resolveKeyPair resolves the init key paths. With both flags it uses any
// existing SSH key pair as given; with one flag it derives the other path.
// With no flags it uses the dedicated key ~/.ssh/hal-vault_ed25519,
// generating it on first use. generated reports whether a new key pair was
// created.
func resolveKeyPair(rPath, iPath string) (recipient, identity string, generated bool, err error) {
	switch {
	case rPath == "" && iPath == "":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", false, fmt.Errorf("locating home directory: %w", err)
		}
		priv := filepath.Join(home, ".ssh", defaultKeyName)
		pub := priv + ".pub"
		switch {
		case fileExists(priv) && fileExists(pub):
			return pub, priv, false, nil
		case fileExists(priv) || fileExists(pub):
			return "", "", false, fmt.Errorf("incomplete key pair at %s(.pub); remove it or pass -r and -i", priv)
		}
		if _, err := vault.GenerateSSHKeyPair(priv, "hal-vault"); err != nil {
			return "", "", false, fmt.Errorf("generating hal-vault SSH key: %w", err)
		}
		return pub, priv, true, nil
	case iPath == "":
		priv := strings.TrimSuffix(rPath, ".pub")
		if priv != rPath && fileExists(priv) {
			return rPath, priv, false, nil
		}
		return "", "", false, errors.New("cannot derive the private key path from -r; use -i")
	case rPath == "":
		if pub := iPath + ".pub"; fileExists(pub) {
			return pub, iPath, false, nil
		}
		return "", "", false, errors.New("cannot find the public key next to -i; use -r")
	default:
		return rPath, iPath, false, nil
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// splitTags parses a comma-separated tag list, trimming whitespace and
// dropping empty elements.
func splitTags(s string) []string {
	var tags []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}
