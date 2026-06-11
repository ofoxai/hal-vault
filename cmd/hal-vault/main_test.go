package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestVaultDir generates an ed25519 SSH key pair on disk and initializes
// a vault with it, returning the vault directory.
func newTestVaultDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(base, "id_ed25519.pub")
	privPath := filepath.Join(base, "id_ed25519")
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(base, "vault")
	if code, _, stderr := runCmd(t, nil, "init", "-r", pubPath, "-i", privPath, "-d", dir); code != 0 {
		t.Fatalf("init failed (%d): %s", code, stderr)
	}
	return dir
}

// runCmd drives run() with a piped stdin and captured stdout/stderr.
func runCmd(t *testing.T, stdin []byte, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, bytes.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

const testSecret = "sk-proj-abcdef1234567890"

func addTestSecret(t *testing.T, dir string) {
	t.Helper()
	code, _, stderr := runCmd(t, []byte(testSecret+"\n"),
		"add", "openai", "-t", "api_key", "--tags", "ai,prod", "-n", "test key", "-d", dir)
	if code != 0 {
		t.Fatalf("add failed (%d): %s", code, stderr)
	}
}

func TestRevealPrintsExactValue(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)

	code, stdout, stderr := runCmd(t, nil, "get", "openai", "--reveal", "-d", dir)
	if code != 0 {
		t.Fatalf("get --reveal failed (%d): %s", code, stderr)
	}
	// Byte-for-byte: the raw value plus exactly one newline, so that
	// KEY=$(hal-vault get x --reveal) captures the exact secret.
	if stdout != testSecret+"\n" {
		t.Errorf("get --reveal output = %q, want %q", stdout, testSecret+"\n")
	}
}

func TestJSONWithoutRevealOmitsValue(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)

	code, stdout, stderr := runCmd(t, nil, "get", "openai", "--json", "-d", dir)
	if code != 0 {
		t.Fatalf("get --json failed (%d): %s", code, stderr)
	}
	if strings.Contains(stdout, testSecret) {
		t.Errorf("get --json without --reveal leaked the raw secret: %s", stdout)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(stdout), &obj); err != nil {
		t.Fatalf("get --json output is not valid JSON: %v\n%s", err, stdout)
	}
	if _, ok := obj["value"]; ok {
		t.Error("get --json without --reveal must not include a \"value\" field")
	}
	if _, ok := obj["masked"]; !ok {
		t.Error("get --json should include a \"masked\" field")
	}
}

func TestJSONWithRevealIncludesValue(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)

	code, stdout, _ := runCmd(t, nil, "get", "openai", "--json", "--reveal", "-d", dir)
	if code != 0 {
		t.Fatal("get --json --reveal failed")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(stdout), &obj); err != nil {
		t.Fatal(err)
	}
	if obj["value"] != testSecret {
		t.Errorf("value field = %v, want the raw secret", obj["value"])
	}
}

func TestMaskedOutputsNeverContainSecret(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)

	for _, args := range [][]string{
		{"get", "openai", "-d", dir},
		{"list", "-d", dir},
		{"list", "--json", "-d", dir},
		{"search", "openai", "-d", dir},
		{"search", "ai", "--json", "-d", dir},
	} {
		code, stdout, stderr := runCmd(t, nil, args...)
		if code != 0 {
			t.Fatalf("%v failed (%d): %s", args, code, stderr)
		}
		if strings.Contains(stdout+stderr, testSecret) {
			t.Errorf("%v leaked the raw secret in its output", args)
		}
	}
}

func TestPipedSecretStripsCRLF(t *testing.T) {
	dir := newTestVaultDir(t)
	code, _, stderr := runCmd(t, []byte("windows-secret-123456\r\n"), "add", "win", "-d", dir)
	if code != 0 {
		t.Fatalf("add failed (%d): %s", code, stderr)
	}
	_, stdout, _ := runCmd(t, nil, "get", "win", "--reveal", "-d", dir)
	if stdout != "windows-secret-123456\n" {
		t.Errorf("stored secret = %q, want CRLF stripped", strings.TrimSuffix(stdout, "\n"))
	}
}

func TestFlagsAfterPositionalArguments(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)

	// -d after the positional argument must still be honored.
	code, stdout, stderr := runCmd(t, nil, "get", "openai", "-d", dir, "--json")
	if code != 0 {
		t.Fatalf("get with trailing flags failed (%d): %s", code, stderr)
	}
	if !strings.Contains(stdout, "openai") {
		t.Errorf("unexpected output: %s", stdout)
	}
}

func TestRmRefusesWithoutForceOnPipe(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)

	code, _, _ := runCmd(t, []byte("y\n"), "rm", "openai", "-d", dir)
	if code == 0 {
		t.Fatal("rm without -f succeeded on a non-terminal stdin")
	}
	// The entry must be untouched.
	if code, _, _ := runCmd(t, nil, "get", "openai", "-d", dir); code != 0 {
		t.Error("entry was removed despite rm refusing")
	}
	// With -f it works.
	if code, _, _ := runCmd(t, nil, "rm", "openai", "-f", "-d", dir); code != 0 {
		t.Error("rm -f failed")
	}
	if code, _, _ := runCmd(t, nil, "get", "openai", "-d", dir); code == 0 {
		t.Error("entry still present after rm -f")
	}
}

func TestAddRejectsBinarySecret(t *testing.T) {
	dir := newTestVaultDir(t)
	code, _, stderr := runCmd(t, []byte("pre\xff\xfepost-binary-key"), "add", "binary", "-d", dir)
	if code == 0 {
		t.Fatal("add accepted a non-UTF-8 secret; it would be silently corrupted")
	}
	if !strings.Contains(stderr, "UTF-8") {
		t.Errorf("error should mention UTF-8: %s", stderr)
	}
}

func TestUpdateValueAndMetadata(t *testing.T) {
	dir := newTestVaultDir(t)
	addTestSecret(t, dir)

	code, _, stderr := runCmd(t, []byte("new-secret-value-7890\n"),
		"update", "openai", "--value", "--tags", "ai,staging", "-d", dir)
	if code != 0 {
		t.Fatalf("update failed (%d): %s", code, stderr)
	}
	_, stdout, _ := runCmd(t, nil, "get", "openai", "--reveal", "-d", dir)
	if stdout != "new-secret-value-7890\n" {
		t.Errorf("updated secret = %q", strings.TrimSuffix(stdout, "\n"))
	}
	_, stdout, _ = runCmd(t, nil, "search", "", "--tag", "staging", "-d", dir)
	if !strings.Contains(stdout, "openai") {
		t.Error("tag update did not take effect")
	}
}

func TestExitCodes(t *testing.T) {
	dir := newTestVaultDir(t)

	// Usage error → 2.
	if code, _, _ := runCmd(t, nil, "get", "-d", dir); code != 2 {
		t.Errorf("get without argument: exit %d, want 2", code)
	}
	// Runtime error (missing entry) → 1.
	if code, _, _ := runCmd(t, nil, "get", "nonexistent", "-d", dir); code != 1 {
		t.Errorf("get of missing entry: exit %d, want 1", code)
	}
	// Unknown command → 2.
	if code, _, _ := runCmd(t, nil, "frobnicate"); code != 2 {
		t.Errorf("unknown command: exit %d, want 2", code)
	}
}

func TestInitGeneratesDedicatedKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // os.UserHomeDir reads $HOME on Unix
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	dir := filepath.Join(home, "vault-a")
	code, stdout, stderr := runCmd(t, nil, "init", "-d", dir)
	if code != 0 {
		t.Fatalf("init failed (%d): %s", code, stderr)
	}
	priv := filepath.Join(home, ".ssh", "hal-vault_ed25519")
	if !strings.Contains(stdout, "generated SSH key pair") {
		t.Errorf("first init should report key generation:\n%s", stdout)
	}
	for _, p := range []string{priv, priv + ".pub"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("dedicated key %s missing: %v", p, err)
		}
	}

	// The generated key must actually work end to end.
	if code, _, stderr := runCmd(t, []byte("dedicated-key-secret-123\n"), "add", "probe", "-d", dir); code != 0 {
		t.Fatalf("add with generated key failed: %s", stderr)
	}
	if _, stdout, _ := runCmd(t, nil, "get", "probe", "--reveal", "-d", dir); stdout != "dedicated-key-secret-123\n" {
		t.Errorf("roundtrip through generated key = %q", stdout)
	}

	// A second init (new vault dir) must reuse the key, not regenerate.
	dirB := filepath.Join(home, "vault-b")
	code, stdout, stderr = runCmd(t, nil, "init", "-d", dirB)
	if code != 0 {
		t.Fatalf("second init failed (%d): %s", code, stderr)
	}
	if strings.Contains(stdout, "generated SSH key pair") {
		t.Errorf("second init must reuse the existing dedicated key:\n%s", stdout)
	}
}
