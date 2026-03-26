package safecrypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type DecodedArtifact struct {
	Name  string
	Bytes []byte
}

var (
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// TryDecodeAll attempts a set of decoders and returns every successful decode result.
// It is intentionally conservative: it only attempts decodes when the input "looks like" the encoding.
func TryDecodeAll(input string) []DecodedArtifact {
	in := strings.TrimSpace(input)
	if in == "" {
		return nil
	}

	out := make([]DecodedArtifact, 0, 4)

	// URL decode (e.g., %7Bflag%7D).
	if strings.Contains(in, "%") || strings.Contains(in, "+") || strings.Contains(strings.ToLower(in), "http") {
		if u, err := url.QueryUnescape(in); err == nil && u != in {
			if b := tryBase64Like(u); len(b) > 0 {
				out = append(out, DecodedArtifact{Name: "url_base64", Bytes: b})
			}
			out = append(out, DecodedArtifact{Name: "url_unescape", Bytes: []byte(u)})
		}
	}

	// Base64.
	if base64Re.MatchString(in) && looksLikeBase64(in) {
		if b, ok := tryBase64Std(in); ok {
			out = append(out, DecodedArtifact{Name: "base64_std", Bytes: b})
		}
		if b, ok := tryBase64Raw(in); ok {
			out = append(out, DecodedArtifact{Name: "base64_raw", Bytes: b})
		}
	}

	// Hex.
	if hexRe.MatchString(strings.TrimSpace(in)) && len(strings.TrimSpace(in))%2 == 0 {
		if b, ok := tryHex(in); ok {
			out = append(out, DecodedArtifact{Name: "hex", Bytes: b})
		}
	}

	// rot13 for classic CTF strings.
	if looksLikeRot13(in) {
		r := rot13(in)
		out = append(out, DecodedArtifact{Name: "rot13", Bytes: []byte(r)})
	}

	// Also try base64 after stripping whitespace/newlines.
	if base64Re.MatchString(in) {
		clean := strings.Map(func(r rune) rune {
			switch r {
			case '\n', '\r', '\t', ' ':
				return -1
			default:
				return r
			}
		}, in)
		if clean != in && looksLikeBase64(clean) {
			if b, ok := tryBase64Std(clean); ok {
				out = append(out, DecodedArtifact{Name: "base64_std_clean", Bytes: b})
			}
			if b, ok := tryBase64Raw(clean); ok {
				out = append(out, DecodedArtifact{Name: "base64_raw_clean", Bytes: b})
			}
		}
	}

	// Deduplicate by length+prefix (simple).
	return dedupeBySignature(out)
}

func dedupeBySignature(in []DecodedArtifact) []DecodedArtifact {
	seen := make(map[string]struct{}, len(in))
	out := make([]DecodedArtifact, 0, len(in))
	for _, a := range in {
		sig := fmt.Sprintf("%d_%x", len(a.Bytes), firstNBytes(a.Bytes, 16))
		if _, ok := seen[sig]; ok {
			continue
		}
		seen[sig] = struct{}{}
		out = append(out, a)
	}
	return out
}

func firstNBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

func looksLikeBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 24 {
		return false
	}
	// Base64 typically comes in blocks; accept padding/no-padding.
	return true
}

func tryBase64Like(s string) []byte {
	s = strings.TrimSpace(s)
	if !base64Re.MatchString(s) {
		return nil
	}
	if b, ok := tryBase64Std(s); ok {
		return b
	}
	if b, ok := tryBase64Raw(s); ok {
		return b
	}
	return nil
}

func tryBase64Std(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	// Remove whitespace, but keep padding.
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		default:
			return r
		}
	}, s)

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func tryBase64Raw(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		default:
			return r
		}
	}, s)

	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func tryHex(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func looksLikeRot13(s string) bool {
	// ROT13 is just a letter substitution; accept alphabetic-heavy inputs.
	// Avoid running it on arbitrary binary/text too frequently.
	letters := 0
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			letters++
		}
		if r >= 'A' && r <= 'Z' {
			letters++
		}
	}
	return len(s) >= 16 && letters >= len(s)*8/10
}

func rot13(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, 'a'+(r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			out = append(out, 'A'+(r-'A'+13)%26)
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

// ReadLimited reads at most maxBytes from a file.
func ReadLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err == nil && st.Size() > maxBytes {
		return readFirstBytes(f, maxBytes)
	}
	return readAllLimited(f, maxBytes)
}

func readAllLimited(f *os.File, maxBytes int64) ([]byte, error) {
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

func readFirstBytes(f *os.File, maxBytes int64) ([]byte, error) {
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// WriteDecodeArtifact persists a decode artifact for later manual inspection.
func WriteDecodeArtifact(runDir, prefix, name, decoded string) error {
	// Best-effort: if it fails, crypto decoding should still succeed.
	outPath := fmt.Sprintf("%s/%s__%s.txt", runDir, prefix, sanitize(name))
	return os.WriteFile(outPath, []byte(decoded), 0644)
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}

