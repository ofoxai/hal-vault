package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ofoxai/hal-vault/vault"
)

// helperEnv makes the test binary act as a child command (see
// TestHelperProcess) instead of running the tests.
const helperEnv = "HAL_VAULT_TEST_HELPER"

// TestHelperProcess is not a test: it is the child command that "hal-vault
// run" starts in the tests below, via the test binary itself so the tests
// need no external programs on any OS.
func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(3)
	}
	cmd, rest := args[1], args[2:]
	switch cmd {
	case "printenv": // KEY=VALUE per argument, on stdout
		for _, k := range rest {
			fmt.Printf("%s=%s\n", k, os.Getenv(k))
		}
	case "stderr": // the values on stderr
		for _, k := range rest {
			fmt.Fprintln(os.Stderr, os.Getenv(k))
		}
	case "split": // the value written in two halves with a pause between
		v := os.Getenv(rest[0])
		os.Stdout.WriteString("<" + v[:len(v)/2])
		os.Stdout.Sync()
		time.Sleep(100 * time.Millisecond)
		os.Stdout.WriteString(v[len(v)/2:] + ">\n")
	case "split-at": // the value's first N bytes, a pause, then the rest
		v := os.Getenv(rest[0])
		n, _ := strconv.Atoi(rest[1])
		os.Stdout.WriteString(v[:n])
		os.Stdout.Sync()
		time.Sleep(100 * time.Millisecond)
		os.Stdout.WriteString(v[n:] + " end\n")
	case "cat":
		io.Copy(os.Stdout, os.Stdin)
	case "exit":
		code, _ := strconv.Atoi(rest[0])
		os.Exit(code)
	case "wait-signal": // print "ready", then exit 42 on SIGINT/SIGTERM
		waitForSignal()
	case "touch":
		os.WriteFile(rest[0], nil, 0o600)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}

// helperArgv is the command line that runs TestHelperProcess as cmd.
func helperArgv(t *testing.T, cmd ...string) []string {
	t.Helper()
	t.Setenv(helperEnv, "1")
	return append([]string{os.Args[0], "-test.run=^TestHelperProcess$", "--"}, cmd...)
}

// runWith runs "hal-vault run -d dir [flags...] -- helper cmd...".
func runWith(t *testing.T, dir string, stdin []byte, flags []string, cmd ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"run", "-d", dir}, flags...)
	args = append(args, "--")
	args = append(args, helperArgv(t, cmd...)...)
	return runCmd(t, stdin, args...)
}

// writeEnvFile writes content to a temporary env file and returns its path.
func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".env.tpl")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// addSecret stores value under label and returns the new entry's ID.
func addSecret(t *testing.T, dir, label, value string) string {
	t.Helper()
	code, stdout, stderr := runCmd(t, []byte(value), "add", label, "-d", dir)
	if code != 0 {
		t.Fatalf("add %s failed (%d): %s", label, code, stderr)
	}
	return strings.Fields(stdout)[1] // "added ID LABEL: MASK"
}

const otherSecret = "ghp-0123456789abcdefghij"

func TestRunInjectsReferencesAndMasksOutput(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)
	id := addSecret(t, dir, "github-pat", otherSecret)
	tpl := writeEnvFile(t, "OPENAI_API_KEY=hal7://openai\n"+
		"export GITHUB_TOKEN=\"hal7://"+id+"\"\n"+
		"PLAIN=hello\n"+
		"NOT_A_REF=foo-hal7://openai\n")

	code, stdout, stderr := runWith(t, dir, nil, []string{"--env-file", tpl},
		"printenv", "OPENAI_API_KEY", "GITHUB_TOKEN", "PLAIN", "NOT_A_REF")
	if code != 0 {
		t.Fatalf("run failed (%d): %s", code, stderr)
	}
	want := "OPENAI_API_KEY=" + vault.Mask(testSecret) + "\n" +
		"GITHUB_TOKEN=" + vault.Mask(otherSecret) + "\n" +
		"PLAIN=hello\n" +
		"NOT_A_REF=foo-hal7://openai\n"
	if stdout != want {
		t.Errorf("stdout:\n got %q\nwant %q", stdout, want)
	}
}

func TestRunNoMaskingPassesRawValues(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)
	tpl := writeEnvFile(t, "OPENAI_API_KEY=hal7://openai\n")

	code, stdout, stderr := runWith(t, dir, nil, []string{"--env-file", tpl, "--no-masking"},
		"printenv", "OPENAI_API_KEY")
	if code != 0 {
		t.Fatalf("run failed (%d): %s", code, stderr)
	}
	if stdout != "OPENAI_API_KEY="+testSecret+"\n" {
		t.Errorf("with --no-masking the child must see and print the raw value, got %q", stdout)
	}
}

func TestRunMasksStderrAndSplitWrites(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)
	tpl := writeEnvFile(t, "OPENAI_API_KEY=hal7://openai\n")

	code, stdout, stderr := runWith(t, dir, nil, []string{"--env-file", tpl}, "stderr", "OPENAI_API_KEY")
	if code != 0 || strings.Contains(stdout+stderr, testSecret) {
		t.Fatalf("stderr not masked (%d): %q", code, stderr)
	}
	if stderr != vault.Mask(testSecret)+"\n" {
		t.Errorf("stderr = %q", stderr)
	}

	// The child writes the secret in two halves with a pause, so it reaches
	// hal-vault in separate reads.
	code, stdout, _ = runWith(t, dir, nil, []string{"--env-file", tpl}, "split", "OPENAI_API_KEY")
	if code != 0 || stdout != "<"+vault.Mask(testSecret)+">\n" {
		t.Errorf("split write: exit %d, stdout %q", code, stdout)
	}
}

// Regression: with a second secret that is a prefix of the first, a write
// boundary at the end of the prefix must not leave the rest of the longer
// secret in the clear.
func TestRunMasksLongerSecretSplitAfterPrefixSecret(t *testing.T) {
	dir := newTestVaultDir(t)
	long, prefix := "sk-test-AAAA1111BBBB2222", "sk-test-AAAA"
	addSecret(t, dir, "openai", long)
	addSecret(t, dir, "prefix", prefix)
	tpl := writeEnvFile(t, "OPENAI_API_KEY=hal7://openai\nPFX=hal7://prefix\n")

	code, stdout, stderr := runWith(t, dir, nil, []string{"--env-file", tpl},
		"split-at", "OPENAI_API_KEY", strconv.Itoa(len(prefix)))
	if code != 0 {
		t.Fatalf("run failed (%d): %s", code, stderr)
	}
	if strings.Contains(stdout, "1111BBBB2222") {
		t.Fatalf("the tail of the longer secret leaked: %q", stdout)
	}
	if want := vault.Mask(long) + " end\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestRunResolvesReferencesFromEnvironment(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)
	t.Setenv("FROM_ENV", "hal7://openai")
	t.Setenv("OVERRIDDEN", "from-env")
	tpl := writeEnvFile(t, "OVERRIDDEN=from-file\n")
	tpl2 := writeEnvFile(t, "OVERRIDDEN=from-second-file\n")

	code, stdout, stderr := runWith(t, dir, nil, []string{"--env-file", tpl, "--env-file", tpl2, "--no-masking"},
		"printenv", "FROM_ENV", "OVERRIDDEN")
	if code != 0 {
		t.Fatalf("run failed (%d): %s", code, stderr)
	}
	want := "FROM_ENV=" + testSecret + "\nOVERRIDDEN=from-second-file\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestRunFailsFastListingEveryFailure(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)
	addSecret(t, dir, "dup", "first-duplicate-value")
	addSecret(t, dir, "dup", "second-duplicate-value")
	tpl := writeEnvFile(t, "GOOD=hal7://openai\n"+
		"MISSING=hal7://no-such-entry\n"+
		"AMBIGUOUS=hal7://dup\n"+
		"EMPTY=hal7://\n")
	marker := filepath.Join(t.TempDir(), "started")

	code, stdout, stderr := runWith(t, dir, nil, []string{"--env-file", tpl}, "touch", marker)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the command was started despite unresolved references")
	}
	for _, want := range []string{"3 of 4 references", "MISSING", "hal7://no-such-entry",
		"AMBIGUOUS", "ambiguous", "EMPTY", "empty reference"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "GOOD") {
		t.Errorf("stderr lists a reference that resolved:\n%s", stderr)
	}
	for _, v := range []string{testSecret, "first-duplicate-value", "second-duplicate-value"} {
		if strings.Contains(stdout+stderr, v) {
			t.Errorf("output leaked a raw value: %s", stdout+stderr)
		}
	}
}

func TestRunPassesExitCodeAndStdin(t *testing.T) {
	dir := newTestVaultDir(t)
	if code, _, _ := runWith(t, dir, nil, nil, "exit", "7"); code != 7 {
		t.Errorf("exit code = %d, want 7", code)
	}
	code, stdout, _ := runWith(t, dir, []byte("piped input\n"), nil, "cat")
	if code != 0 || stdout != "piped input\n" {
		t.Errorf("stdin passthrough: exit %d, stdout %q", code, stdout)
	}
}

func TestRunWithoutReferencesNeedsNoVault(t *testing.T) {
	// No hal7:// values anywhere: the vault is never opened, so a missing
	// vault is not an error.
	missing := filepath.Join(t.TempDir(), "no-vault")
	code, stdout, stderr := runWith(t, missing, nil, nil, "printenv", "HAL_VAULT_TEST_HELPER")
	if code != 0 || stdout != "HAL_VAULT_TEST_HELPER=1\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestRunUsageErrors(t *testing.T) {
	dir := newTestVaultDir(t)
	if code, _, _ := runCmd(t, nil, "run", "-d", dir); code != 2 {
		t.Errorf("run without a command: exit %d, want 2", code)
	}
	if code, _, _ := runCmd(t, nil, "run", "-d", dir, "--env-file", filepath.Join(dir, "absent"), "--", "x"); code != 1 {
		t.Errorf("run with a missing env file: exit %d, want 1", code)
	}
}

func TestCheck(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)
	good := writeEnvFile(t, "OPENAI_API_KEY=hal7://openai\nPLAIN=1\n")

	code, stdout, stderr := runCmd(t, nil, "check", "-d", dir, "--env-file", good)
	if code != 0 {
		t.Fatalf("check failed (%d): %s", code, stderr)
	}
	for _, want := range []string{"OPENAI_API_KEY", "hal7://openai", vault.Mask(testSecret), "all 1 references resolve"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("check output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout+stderr, testSecret) {
		t.Error("check leaked the raw secret")
	}

	bad := writeEnvFile(t, "A=hal7://missing-a\nB=hal7://missing-b\nC=hal7://openai\n")
	code, _, stderr = runCmd(t, nil, "check", "-d", dir, "--env-file", bad)
	if code != 1 {
		t.Errorf("check with failures: exit %d, want 1", code)
	}
	for _, want := range []string{"2 of 3", "missing-a", "missing-b"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("check stderr lacks %q:\n%s", want, stderr)
		}
	}

	none := writeEnvFile(t, "PLAIN=1\n")
	if code, stdout, _ := runCmd(t, nil, "check", "-d", dir, "--env-file", none); code != 0 ||
		!strings.Contains(stdout, "no hal7:// references") {
		t.Errorf("check without references: exit %d, %q", code, stdout)
	}
}

func TestResolveRefs(t *testing.T) {
	db := &vault.DB{Version: vault.SchemaVersion}
	for _, e := range []vault.Entry{
		{ID: "aaaaaa", Label: "openai", Value: testSecret},
		{ID: "bbbbbb", Label: "dup", Value: "v1-value"},
		{ID: "cccccc", Label: "dup", Value: "v2-value"},
	} {
		if err := db.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	refs := []reference{
		{Key: "BY_LABEL", Ref: "OpenAI"}, // labels match case-insensitively, as in get
		{Key: "BY_ID", Ref: "cccccc"},
		{Key: "AMBIGUOUS", Ref: "dup"},
		{Key: "MISSING", Ref: "nope"},
	}
	if resolveRefs(db, refs) {
		t.Fatal("resolveRefs reported success with failures")
	}
	if refs[0].Err != nil || refs[0].Entry.ID != "aaaaaa" {
		t.Errorf("label lookup: %+v", refs[0])
	}
	if refs[1].Err != nil || refs[1].Entry.Value != "v2-value" {
		t.Errorf("ID lookup: %+v", refs[1].Err)
	}
	if err := refs[2].Err; err == nil || !strings.Contains(err.Error(), "bbbbbb") || !strings.Contains(err.Error(), "cccccc") {
		t.Errorf("ambiguous label should list candidate IDs: %v", err)
	}
	if refs[3].Err == nil {
		t.Error("missing entry resolved")
	}
}
