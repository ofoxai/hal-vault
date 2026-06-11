package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateSSHKeyPair(t *testing.T) {
	priv := filepath.Join(t.TempDir(), "ssh", "hal-vault_ed25519")
	pub, err := GenerateSSHKeyPair(priv, "hal-vault")
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair: %v", err)
	}
	if pub != priv+".pub" {
		t.Errorf("pub path = %q, want %q", pub, priv+".pub")
	}

	// The generated keys must round-trip through the vault's own crypto.
	pubBytes, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(pubBytes)), " hal-vault") {
		t.Errorf("public key %q lacks the hal-vault comment", string(pubBytes))
	}
	r, err := ParseRecipient(pubBytes)
	if err != nil {
		t.Fatalf("generated public key not parseable: %v", err)
	}
	privBytes, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseIdentity(privBytes, nil)
	if err != nil {
		t.Fatalf("generated private key not parseable: %v", err)
	}
	ciphertext, err := Encrypt(r, []byte("roundtrip"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Decrypt(id, ciphertext)
	if err != nil {
		t.Fatalf("decrypting with generated key: %v", err)
	}
	if string(plaintext) != "roundtrip" {
		t.Errorf("roundtrip = %q", plaintext)
	}

	// Modes (POSIX only).
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(priv); info.Mode().Perm() != 0o600 {
			t.Errorf("private key mode = %o, want 600", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(priv)); info.Mode().Perm() != 0o700 {
			t.Errorf("key dir mode = %o, want 700", info.Mode().Perm())
		}
	}

	// Never overwrite an existing key.
	if _, err := GenerateSSHKeyPair(priv, "hal-vault"); err == nil {
		t.Fatal("GenerateSSHKeyPair overwrote an existing key")
	}
}
