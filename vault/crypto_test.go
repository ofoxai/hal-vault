package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testKeyPair is an SSH key pair in the on-disk formats the library consumes:
// authorized_keys format for the public key, OpenSSH PEM for the private key.
type testKeyPair struct {
	public  []byte
	private []byte
	// raw is the unmarshaled private key, kept for passphrase-encrypted
	// re-marshaling in tests.
	raw any
}

var (
	ed25519Once sync.Once
	ed25519Key  testKeyPair
	ed25519Err  error

	rsaOnce sync.Once
	rsaKey  testKeyPair
	rsaErr  error
)

// marshalSSHKeyPair converts a raw key pair into authorized_keys and
// OpenSSH PEM formats.
func marshalSSHKeyPair(pub any, priv any) (testKeyPair, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return testKeyPair{}, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return testKeyPair{}, err
	}
	return testKeyPair{
		public:  ssh.MarshalAuthorizedKey(sshPub),
		private: pem.EncodeToMemory(block),
		raw:     priv,
	}, nil
}

// testEd25519Key returns a process-wide cached ed25519 SSH key pair.
func testEd25519Key(t *testing.T) testKeyPair {
	t.Helper()
	ed25519Once.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			ed25519Err = err
			return
		}
		ed25519Key, ed25519Err = marshalSSHKeyPair(pub, priv)
	})
	if ed25519Err != nil {
		t.Fatalf("generating ed25519 key: %v", ed25519Err)
	}
	return ed25519Key
}

// testRSAKey returns a process-wide cached RSA-2048 SSH key pair.
func testRSAKey(t *testing.T) testKeyPair {
	t.Helper()
	rsaOnce.Do(func() {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			rsaErr = err
			return
		}
		rsaKey, rsaErr = marshalSSHKeyPair(&priv.PublicKey, priv)
	})
	if rsaErr != nil {
		t.Fatalf("generating RSA key: %v", rsaErr)
	}
	return rsaKey
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		key  func(*testing.T) testKeyPair
	}{
		{"ed25519", testEd25519Key},
		{"rsa", testRSAKey},
	}
	plaintexts := [][]byte{
		[]byte(""),
		[]byte("hello"),
		[]byte(`{"version":1,"entries":[]}`),
		bytes.Repeat([]byte{0xff, 0x00}, 4096),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.key(t)
			r, err := ParseRecipient(kp.public)
			if err != nil {
				t.Fatalf("ParseRecipient: %v", err)
			}
			id, err := ParseIdentity(kp.private, nil)
			if err != nil {
				t.Fatalf("ParseIdentity: %v", err)
			}
			for _, plaintext := range plaintexts {
				ciphertext, err := Encrypt(r, plaintext)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) {
					t.Fatal("ciphertext is not in the age binary format")
				}
				if len(plaintext) > 0 && bytes.Contains(ciphertext, plaintext) {
					t.Fatal("ciphertext contains the plaintext")
				}
				got, err := Decrypt(id, ciphertext)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("roundtrip mismatch: got %d bytes, want %d bytes", len(got), len(plaintext))
				}
			}
		})
	}
}

func TestDecryptWrongKey(t *testing.T) {
	ed := testEd25519Key(t)
	rs := testRSAKey(t)

	tests := []struct {
		name       string
		encryptTo  []byte
		decryptKey []byte
	}{
		{"encrypt ed25519, decrypt rsa", ed.public, rs.private},
		{"encrypt rsa, decrypt ed25519", rs.public, ed.private},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseRecipient(tt.encryptTo)
			if err != nil {
				t.Fatalf("ParseRecipient: %v", err)
			}
			ciphertext, err := Encrypt(r, []byte("top secret"))
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			id, err := ParseIdentity(tt.decryptKey, nil)
			if err != nil {
				t.Fatalf("ParseIdentity: %v", err)
			}
			if _, err := Decrypt(id, ciphertext); err == nil {
				t.Fatal("Decrypt with the wrong key succeeded, want error")
			}
		})
	}
}

func TestParseRecipientErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte("")},
		{"whitespace only", []byte("  \n\t")},
		{"garbage", []byte("not an ssh key")},
		{"truncated", []byte("ssh-ed25519 AAAA")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseRecipient(tt.data); err == nil {
				t.Errorf("ParseRecipient(%q) succeeded, want error", tt.data)
			}
		})
	}
}

func TestParseIdentityMalformed(t *testing.T) {
	if _, err := ParseIdentity([]byte("not a private key"), nil); err == nil {
		t.Fatal("ParseIdentity with garbage succeeded, want error")
	}
}

// encryptedTestKey returns the ed25519 test key re-marshaled as a
// passphrase-protected OpenSSH private key.
func encryptedTestKey(t *testing.T, passphrase []byte) testKeyPair {
	t.Helper()
	kp := testEd25519Key(t)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(kp.raw, "", passphrase)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	return testKeyPair{public: kp.public, private: pem.EncodeToMemory(block)}
}

func TestParseIdentityPassphraseProtected(t *testing.T) {
	passphrase := []byte("correct horse battery staple")
	kp := encryptedTestKey(t, passphrase)

	r, err := ParseRecipient(kp.public)
	if err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}
	ciphertext, err := Encrypt(r, []byte("locked away"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("nil prompt fails cleanly", func(t *testing.T) {
		_, err := ParseIdentity(kp.private, nil)
		if err == nil {
			t.Fatal("ParseIdentity with nil prompt succeeded, want error")
		}
		if !strings.Contains(err.Error(), "passphrase") {
			t.Errorf("error %q does not mention passphrase", err)
		}
	})

	t.Run("correct passphrase decrypts", func(t *testing.T) {
		id, err := ParseIdentity(kp.private, func() ([]byte, error) {
			return passphrase, nil
		})
		if err != nil {
			t.Fatalf("ParseIdentity: %v", err)
		}
		got, err := Decrypt(id, ciphertext)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(got) != "locked away" {
			t.Fatalf("roundtrip mismatch: got %q", got)
		}
	})

	t.Run("wrong passphrase fails", func(t *testing.T) {
		id, err := ParseIdentity(kp.private, func() ([]byte, error) {
			return []byte("wrong"), nil
		})
		if err != nil {
			t.Fatalf("ParseIdentity: %v", err)
		}
		if _, err := Decrypt(id, ciphertext); err == nil {
			t.Fatal("Decrypt with wrong passphrase succeeded, want error")
		}
	})
}
