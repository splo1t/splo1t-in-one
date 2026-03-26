package util

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CreateRunDir creates a writable directory for logs and artifacts.
func CreateRunDir() (string, error) {
	base := "/tmp"
	// If /tmp isn't writable (rare under sudo), fall back to $PWD.
	if !isWritableDir(base) {
		if cwd, err := os.Getwd(); err == nil && isWritableDir(cwd) {
			base = cwd
		}
	}
	ts := time.Now().UTC().Format("20060102_150405")
	name := fmt.Sprintf("splo1t_runs_%d_%s", os.Getpid(), ts)
	p := filepath.Join(base, name)
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", err
	}
	return p, nil
}

func isWritableDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	testFile := filepath.Join(path, ".splo1t_write_test")
	f, err := os.Create(testFile)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(testFile)
	return true
}

