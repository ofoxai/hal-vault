//go:build windows

package vault

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lockDir takes an exclusive lock on the vault's lock file, blocking until
// it is available. The returned function releases the lock. The OS releases
// LockFileEx locks automatically if the process dies, so a crash cannot
// leave the vault permanently locked.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped)); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		windows.UnlockFileEx(h, 0, 1, 0, new(windows.Overlapped))
		f.Close()
	}, nil
}
