package pivot

import (
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ResolvePlan returns an ordered list of module names to execute.
// The first module comes from the user selection, but target heuristics can override/pivot.
func ResolvePlan(selected string, target string) []string {
	selected = strings.ToLower(strings.TrimSpace(selected))
	if selected == "" {
		return nil
	}

	// Heuristic classification.
	kind := classifyTarget(target)

	// Build plan.
	switch kind {
	case "crypto":
		return []string{"crypto"}
	case "file_binary":
		return dedupeOrdered([]string{"reverse", "crypto"})
	case "file_forensics":
		return dedupeOrdered([]string{"forensics", "crypto"})
	case "pwn":
		// Shell-ish target hint.
		return dedupeOrdered([]string{"pwn", "crypto"})
	case "web":
		// If user selected web, execute web discovery only.
		if selected == "web" {
			return []string{"web"}
		}
		// Otherwise respect selection.
		return []string{selectedToModule(selected)}
	default:
		// Unknown: run what the user selected.
		return []string{selectedToModule(selected)}
	}
}

func selectedToModule(selected string) string {
	switch selected {
	case "web":
		return "web"
	case "pwn":
		return "pwn"
	case "reverse":
		return "reverse"
	case "forensics":
		return "forensics"
	case "crypto":
		return "crypto"
	case "misc":
		return "misc"
	default:
		return "misc"
	}
}

func dedupeOrdered(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func classifyTarget(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return "unknown"
	}

	// If it's a file path, inspect bytes and extension.
	if fi, err := os.Stat(t); err == nil && fi.Mode().IsRegular() {
		return classifyFile(t, fi.Size())
	}

	// Shell-ish hints.
	low := strings.ToLower(t)
	if strings.Contains(low, "shell") || strings.Contains(low, "www-data") || strings.Contains(low, "meterpreter") || strings.Contains(low, "session") {
		return "pwn"
	}

	// URL-ish.
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.Contains(low, "://") {
		return "web"
	}

	// Host-ish (IP or domain).
	if ip := net.ParseIP(t); ip != nil {
		return "web"
	}
	if looksLikeDomain(t) {
		return "web"
	}

	// Otherwise treat as text/encoded.
	if looksLikeBase64(t) || looksLikeHex(t) || strings.Contains(t, "-----BEGIN") {
		return "crypto"
	}
	return "unknown"
}

func classifyFile(path string, size int64) string {
	ext := strings.ToLower(filepath.Ext(path))
	// Extension-based quick paths.
	switch ext {
	case ".elf", ".exe", ".dll":
		return "file_binary"
	case ".pcap", ".pcapng":
		return "file_forensics"
	}

	f, err := os.Open(path)
	if err != nil {
		return "file_forensics"
	}
	defer f.Close()

	var hdr [8]byte
	n, _ := io.ReadFull(f, hdr[:])
	if n >= 4 {
		// ELF magic.
		if hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' {
			return "file_binary"
		}
		// PE magic "MZ".
		if hdr[0] == 'M' && hdr[1] == 'Z' {
			return "file_binary"
		}
	}

	// Try to infer binary-vs-text by extension and size.
	if size < 1024*512 {
		return "file_forensics"
	}
	return "file_forensics"
}

var (
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	// Very lightweight domain check (requires dots + a TLD).
	domainRe = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$`)
)

func looksLikeBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 24 || len(s)%4 != 0 && !strings.HasSuffix(s, "=") {
		return false
	}
	if !base64Re.MatchString(s) {
		return false
	}
	return true
}

func looksLikeHex(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 24 || len(s)%2 != 0 {
		return false
	}
	if !hexRe.MatchString(s) {
		return false
	}
	// Quick validity check.
	_, err := hex.DecodeString(s[:min(128, len(s))])
	return err == nil
}

func looksLikeDomain(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	return domainRe.MatchString(s)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

