package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/ofoxai/hal-vault/vault"
)

// refScheme marks an environment value as a reference to a vault entry:
// KEY=hal7://<label-or-id>. Only a value that starts with the scheme is a
// reference; there is no interpolation inside longer strings.
const refScheme = "hal7://"

// exitCodeError carries a child process exit code through run unchanged.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// env is an ordered environment: later Sets override earlier values but
// keep the variable's original position.
type env struct {
	keys []string
	vals map[string]string
}

func newEnv() *env { return &env{vals: make(map[string]string)} }

func (e *env) Set(k, v string) {
	if _, ok := e.vals[k]; !ok {
		e.keys = append(e.keys, k)
	}
	e.vals[k] = v
}

func (e *env) Environ() []string {
	out := make([]string, 0, len(e.keys))
	for _, k := range e.keys {
		out = append(out, k+"="+e.vals[k])
	}
	return out
}

// buildEnv layers the process environment and then each env file in order.
func buildEnv(environ []string, files []string) (*env, error) {
	e := newEnv()
	for _, kv := range environ {
		// Windows keeps per-drive entries like "=C:=C:\dir": skip the
		// leading '=' when looking for the separator.
		if i := strings.IndexByte(kv[min(1, len(kv)):], '='); i >= 0 {
			i += min(1, len(kv))
			e.Set(kv[:i], kv[i+1:])
		}
	}
	for _, f := range files {
		vars, err := readEnvFile(f)
		if err != nil {
			return nil, err
		}
		for _, v := range vars {
			e.Set(v.Key, v.Value)
		}
	}
	return e, nil
}

// reference is one KEY=hal7://ref found in the environment.
type reference struct {
	Key   string
	Ref   string // the part after hal7://
	Entry *vault.Entry
	Err   error
}

// findRefs returns the references in e, sorted by key.
func findRefs(e *env) []reference {
	var refs []reference
	for _, k := range e.keys {
		if ref, ok := strings.CutPrefix(e.vals[k], refScheme); ok {
			refs = append(refs, reference{Key: k, Ref: ref})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Key < refs[j].Key })
	return refs
}

// resolveRefs looks every reference up in one loaded database, with the same
// ID-or-label rules as get. It records each failure instead of stopping at
// the first, and reports whether all succeeded.
func resolveRefs(db *vault.DB, refs []reference) bool {
	ok := true
	for i := range refs {
		r := &refs[i]
		if r.Ref == "" {
			r.Err = errors.New("empty reference")
		} else {
			r.Entry, r.Err = db.Get(r.Ref)
		}
		if r.Err != nil {
			ok = false
		}
	}
	return ok
}

// loadRefs builds the environment, finds its references and resolves them
// with a single vault decryption. The vault is not opened at all when there
// are no references. Any unresolved reference fails the whole call with an
// error listing every failure (keys and references only, never values).
func loadRefs(dir string, files []string, stdin io.Reader, stderr io.Writer) (*env, []reference, error) {
	e, err := buildEnv(os.Environ(), files)
	if err != nil {
		return nil, nil, err
	}
	refs := findRefs(e)
	if len(refs) == 0 {
		return e, nil, nil
	}
	s, err := openStore(dir, stdin, stderr)
	if err != nil {
		return nil, nil, err
	}
	db, err := s.Load()
	if err != nil {
		return nil, nil, err
	}
	if !resolveRefs(db, refs) {
		var b strings.Builder
		var failed int
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, r := range refs {
			if r.Err != nil {
				failed++
				fmt.Fprintf(tw, "\n  %s\t%s%s\t%v", r.Key, refScheme, r.Ref, r.Err)
			}
		}
		tw.Flush()
		return nil, nil, fmt.Errorf("%d of %d references could not be resolved:%s",
			failed, len(refs), b.String())
	}
	return e, refs, nil
}

func cmdRun(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "run", "run [--env-file FILE]... [--no-masking] [-d DIR] -- CMD [ARGS...]")
	var files stringList
	fs.Var(&files, "env-file", "dotenv file to load (repeatable; later files win)")
	noMasking := fs.Bool("no-masking", false, "do not mask secrets in the command's output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errFlagParse
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return usageErrorf("run needs a command: hal-vault run [flags] -- CMD [ARGS...]")
	}

	e, refs, err := loadRefs(*dir, files, stdin, stderr)
	if err != nil {
		return err
	}
	var secrets []string
	for _, r := range refs {
		e.Set(r.Key, r.Entry.Value)
		secrets = append(secrets, r.Entry.Value)
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = e.Environ()
	cmd.Stdin = stdin
	cmd.Stdout, cmd.Stderr = stdout, stderr
	var redactors []*redactor
	if !*noMasking && len(secrets) > 0 {
		ro, re := newRedactor(stdout, secrets), newRedactor(stderr, secrets)
		cmd.Stdout, cmd.Stderr = ro, re
		redactors = append(redactors, ro, re)
	}
	return runChild(cmd, redactors)
}

// runChild starts cmd, forwards SIGINT/SIGTERM to it, waits, flushes the
// redactors and turns the child's exit status into an exitCodeError.
func runChild(cmd *exec.Cmd, redactors []*redactor) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigs:
				cmd.Process.Signal(sig) // best effort; unsupported on Windows
			case <-done:
				return
			}
		}
	}()
	waitErr := cmd.Wait()
	for _, r := range redactors {
		if err := r.Flush(); err != nil && waitErr == nil {
			waitErr = err
		}
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		return &exitCodeError{code: exitCode(ee.ProcessState)}
	}
	return waitErr
}

// exitCode maps a finished process to a shell-style exit code: its own exit
// status, or 128+N when it was killed by signal N.
func exitCode(ps *os.ProcessState) int {
	if code := ps.ExitCode(); code >= 0 {
		return code
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 1
}

func cmdCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dir := newFlagSet(stderr, "check", "check [--env-file FILE]... [-d DIR]")
	var files stringList
	fs.Var(&files, "env-file", "dotenv file to check (repeatable; later files win)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageErrorf("check takes no arguments")
	}

	_, refs, err := loadRefs(*dir, files, stdin, stderr)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		fmt.Fprintln(stdout, "no hal7:// references found.")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	for _, r := range refs {
		fmt.Fprintf(tw, "%s\t%s%s\t%s %s: %s\n", r.Key, refScheme, r.Ref, r.Entry.ID, r.Entry.Label, r.Entry.Masked())
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "all %d references resolve.\n", len(refs))
	return nil
}
