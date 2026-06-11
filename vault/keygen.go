package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// GenerateSSHKeyPair creates a new ed25519 SSH key pair at privPath (mode
// 0600) and privPath+".pub" (mode 0644), creating the parent directory with
// mode 0700 if needed. It refuses to overwrite existing files. The comment
// is embedded in both keys, OpenSSH style.
func GenerateSSHKeyPair(privPath, comment string) (pubPath string, err error) {
	pubPath = privPath + ".pub"
	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return "", err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}

	// O_EXCL: never overwrite an existing key.
	f, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, werr := f.Write(pem.EncodeToMemory(block))
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(privPath)
		return "", err
	}

	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	if comment != "" {
		pubBytes = append(bytes.TrimSuffix(pubBytes, []byte("\n")), ' ')
		pubBytes = append(pubBytes, comment...)
		pubBytes = append(pubBytes, '\n')
	}
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		os.Remove(privPath)
		return "", err
	}
	return pubPath, nil
}
