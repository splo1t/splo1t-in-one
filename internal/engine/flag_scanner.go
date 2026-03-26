package engine

import (
	"fmt"
	"regexp"
	"sync"
)

type FlagScanner struct {
	re *regexp.Regexp

	mu   sync.Mutex
	seen map[string]struct{}
	n    int

	// Keep a rolling buffer so regex matches that span chunk boundaries still work.
	// 64KiB is a pragmatic compromise: enough for common flags, bounded memory.
	buf []byte
}

func NewFlagScanner(flagRegex string) (*FlagScanner, error) {
	re, err := regexp.Compile(flagRegex)
	if err != nil {
		return nil, err
	}
	return &FlagScanner{
		re:   re,
		seen: make(map[string]struct{}),
		buf:  make([]byte, 0, 64*1024),
	}, nil
}

// Consume scans streamed bytes for new flag matches.
// It is safe to call concurrently.
func (fs *FlagScanner) Consume(p []byte) {
	if len(p) == 0 {
		return
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Append new data to rolling buffer.
	fs.buf = append(fs.buf, p...)
	if len(fs.buf) > 64*1024 {
		// Trim oldest bytes.
		fs.buf = fs.buf[len(fs.buf)-(64*1024):]
	}

	matches := fs.re.FindAllString(string(fs.buf), -1)
	for _, m := range matches {
		if _, ok := fs.seen[m]; ok {
			continue
		}
		fs.seen[m] = struct{}{}
		fs.n++

		// Print immediately as requested.
		// Yellow highlight for readability.
		fmt.Printf("\033[1;33m[+] FLAG DETECTED:\033[0m %s\n", m)
	}
}

func (fs *FlagScanner) Count() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.n
}

// FlushFinal is a no-op for now; kept for future improvements (e.g., final buffer scan).
func (fs *FlagScanner) FlushFinal() error {
	return nil
}

