//go:build !windows

package vault

import (
	"os"
	"path/filepath"
	"syscall"
)

// lockDir takes an exclusive advisory lock on the vault's lock file,
// blocking until it is available. The returned function releases the lock.
// The kernel releases flock locks automatically if the process dies, so a
// crash cannot leave the vault permanently locked.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
