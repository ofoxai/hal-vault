package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// ParseRecipient parses an SSH public key (authorized_keys format) into an
// age recipient. Supported key types are ssh-ed25519 and ssh-rsa.
func ParseRecipient(data []byte) (age.Recipient, error) {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil, errors.New("empty SSH public key")
	}
	return agessh.ParseRecipient(s)
}

// ParseIdentity parses an SSH private key (OpenSSH format) into an age
// identity. If the key is passphrase-protected, prompt is invoked lazily to
// obtain the passphrase when decryption requires it. A nil prompt causes an
// error for passphrase-protected keys.
func ParseIdentity(data []byte, prompt func() ([]byte, error)) (age.Identity, error) {
	id, err := agessh.ParseIdentity(data)
	if err == nil {
		return id, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, fmt.Errorf("malformed SSH identity: %v", err)
	}
	if missing.PublicKey == nil {
		return nil, errors.New("passphrase-protected SSH key does not embed its public key; only OpenSSH-format keys are supported")
	}
	if prompt == nil {
		return nil, errors.New("SSH key is passphrase-protected but no passphrase prompt is available")
	}
	return agessh.NewEncryptedSSHIdentity(missing.PublicKey, data, prompt)
}

// Encrypt encrypts plaintext to r using the age binary format.
func Encrypt(r age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts an age-encrypted ciphertext using identity i.
func Decrypt(i age.Identity, ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), i)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
