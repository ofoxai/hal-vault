package vault

import (
	"crypto/rand"
	"errors"
	"time"
)

// Entry is a single secret stored in the vault.
type Entry struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	Tags      []string  `json:"tags,omitempty"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EntryTypes lists the valid values for Entry.Type.
var EntryTypes = []string{
	"api_key", "password", "token", "ssh_key", "cert", "identity", "other",
}

// ValidType reports whether t is a valid entry type.
func ValidType(t string) bool {
	for _, v := range EntryTypes {
		if t == v {
			return true
		}
	}
	return false
}

// idAlphabet is the Crockford base32 alphabet, lowercase
// (digits and letters excluding i, l, o, u).
const idAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// idLength is the number of characters in a generated entry ID.
const idLength = 6

// NewID generates a random 6-character lowercase Crockford base32 ID
// that does not collide with any key in existing.
func NewID(existing map[string]bool) (string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		buf := make([]byte, idLength)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		id := make([]byte, idLength)
		for i, b := range buf {
			id[i] = idAlphabet[int(b)%len(idAlphabet)]
		}
		if !existing[string(id)] {
			return string(id), nil
		}
	}
	return "", errors.New("could not generate a unique ID")
}

// Masked returns the entry value masked for safe display.
func (e *Entry) Masked() string {
	return Mask(e.Value)
}
