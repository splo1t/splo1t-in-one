package modules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/splo1t/splo1t/internal/engine"
)

func ModuleCommandSpecs(mod string, target string) []engine.CommandSpec {
	mod = strings.ToLower(strings.TrimSpace(mod))
	t := strings.TrimSpace(target)

	// Treat target as optional; modules can skip if not applicable.
	switch mod {
	case "web":
		return webSpecs(t)
	case "pwn":
		return pwnSpecs(t)
	case "reverse":
		return reverseSpecs(t)
	case "forensics":
		return forensicsSpecs(t)
	case "crypto":
		// External crypto is intentionally minimal; in-process decoder already runs in runner.
		// Still attempt base64 decoding via command tools when available.
		return cryptoSpecs(t)
	case "misc":
		return miscSpecs(t)
	default:
		return miscSpecs(t)
	}
}

func isLikelyURL(s string) bool {
	low := strings.ToLower(s)
	return strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.Contains(low, "://")
}

func webSpecs(target string) []engine.CommandSpec {
	host := normalizeHTTPHost(target)
	if host == "" {
		return []engine.CommandSpec{}
	}

	// Directory wordlist (best-effort). If not found, only run nmap.
	wordlist := bestDirWordlist()

	httpBase := "http://" + host
	httpsBase := "https://" + host

	cmds := []engine.CommandSpec{
		{
			Name:    "nmap_service_discovery",
			Required: false,
			Command: []string{"nmap", "-Pn", "-sV", "--reason", "-T4", host},
		},
	}

	// Lightweight web "fetch" for banner/content scanning.
	cmds = append(cmds,
		engine.CommandSpec{Name: "curl_fetch_http", Required: false, Command: []string{"curl", "-sSL", "--max-time", "15", httpBase}},
		engine.CommandSpec{Name: "curl_fetch_https", Required: false, Command: []string{"curl", "-k", "-sSL", "--max-time", "15", httpsBase}},
	)

	if wordlist != "" {
		// ffuf
		cmds = append(cmds,
			engine.CommandSpec{Name: "ffuf_http", Required: false, Command: []string{"ffuf", "-u", httpBase + "/FUZZ", "-w", wordlist, "-t", "50", "-timeout", "15", "-fc", "404", "-ac"}},
			engine.CommandSpec{Name: "ffuf_https", Required: false, Command: []string{"ffuf", "-u", httpsBase + "/FUZZ", "-w", wordlist, "-t", "50", "-timeout", "15", "-k", "-fc", "404", "-ac"}},
		)

		// gobuster
		cmds = append(cmds,
			engine.CommandSpec{Name: "gobuster_http", Required: false, Command: []string{"gobuster", "dir", "-u", httpBase, "-w", wordlist, "-t", "50", "-q"}},
			engine.CommandSpec{Name: "gobuster_https", Required: false, Command: []string{"gobuster", "dir", "-u", httpsBase, "-w", wordlist, "-t", "50", "-q", "--insecure"}},
		)

		// dirsearch
		cmds = append(cmds,
			engine.CommandSpec{Name: "dirsearch_http", Required: false, Command: []string{"dirsearch", "-u", httpBase, "-w", wordlist, "-e", "php,html,txt,js,css", "-r", "--quiet"}},
			engine.CommandSpec{Name: "dirsearch_https", Required: false, Command: []string{"dirsearch", "-u", httpsBase, "-w", wordlist, "-e", "php,html,txt,js,css", "-r", "--quiet", "-k"}},
		)

		// feroxbuster
		cmds = append(cmds,
			engine.CommandSpec{Name: "feroxbuster_http", Required: false, Command: []string{"feroxbuster", "-u", httpBase, "-w", wordlist, "-t", "50", "-q", "-e", "php,html,txt"}},
			engine.CommandSpec{Name: "feroxbuster_https", Required: false, Command: []string{"feroxbuster", "-u", httpsBase, "-w", wordlist, "-t", "50", "-q", "-e", "php,html,txt", "--insecure"}},
		)

		// wfuzz
		cmds = append(cmds,
			engine.CommandSpec{Name: "wfuzz_http", Required: false, Command: []string{"wfuzz", "-c", "-z", "file," + wordlist, "-hc", "404", httpBase + "/FUZZ"}},
			engine.CommandSpec{Name: "wfuzz_https", Required: false, Command: []string{"wfuzz", "-c", "-z", "file," + wordlist, "-hc", "404", httpsBase + "/FUZZ"}},
		)
	}

	// Nuclei (best-effort). Requires templates; still skip gracefully if not installed.
	cmds = append(cmds,
		engine.CommandSpec{Name: "nuclei_http", Required: false, Command: []string{"nuclei", "-u", httpBase, "-silent"}},
		engine.CommandSpec{Name: "nuclei_https", Required: false, Command: []string{"nuclei", "-u", httpsBase, "-silent", "-k"}},
	)

	return cmds
}

func normalizeHTTPHost(input string) string {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}
	// Strip scheme if present.
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	// Strip path/query; keep host[:port].
	if idx := strings.IndexAny(s, "/?"); idx >= 0 {
		s = s[:idx]
	}
	// If still looks like "http://..." due to casing.
	if isLikelyURL(s) {
		return ""
	}
	// For simple cases, accept as-is.
	if strings.Contains(s, " ") {
		return ""
	}
	// Very small sanity check.
	if len(s) < 3 {
		return ""
	}
	return s
}

func bestDirWordlist() string {
	candidates := []string{
		"/usr/share/wordlists/raft-medium-directories.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Size() > 0 {
			return c
		}
	}
	// Fallback: some systems mount smaller wordlists; leave empty if none.
	return ""
}

func reverseSpecs(target string) []engine.CommandSpec {
	// Only operate on files.
	if target == "" {
		return []engine.CommandSpec{}
	}
	fi, err := os.Stat(target)
	if err != nil || !fi.Mode().IsRegular() {
		return []engine.CommandSpec{}
	}
	// Quick check to avoid calling tools with empty/obviously text targets.
	// This is best-effort; tools will still fail gracefully.
	ext := strings.ToLower(filepath.Ext(target))
	reverseOnExt := map[string]bool{
		".elf": true, ".exe": true, ".dll": true, ".so": true, ".bin": true,
	}
	if len(reverseOnExt) > 0 && !reverseOnExt[ext] {
		// Still allow generic reverse attempt if file name looks binary-ish.
		// Users can refine the pivot selection with their initial menu choice.
	}

	return []engine.CommandSpec{
		{Name: "file_type", Required: false, Command: []string{"file", target}},
		{Name: "strings", Required: false, Command: []string{"strings", "-a", "-n", "4", target}},
		{Name: "readelf", Required: false, Command: []string{"readelf", "-a", target}},
	}
}

func forensicsSpecs(target string) []engine.CommandSpec {
	// For local file paths, try common extraction/inspection tools.
	fi, err := os.Stat(target)
	if err != nil || !fi.Mode().IsRegular() {
		return []engine.CommandSpec{}
	}
	return []engine.CommandSpec{
		{Name: "file_type", Required: false, Command: []string{"file", target}},
		{Name: "exiftool", Required: false, Command: []string{"exiftool", target}},
		{Name: "binwalk", Required: false, Command: []string{"binwalk", target}},
		{Name: "binwalk_extract", Required: false, Command: []string{"binwalk", "-e", target}},
	}
}

func cryptoSpecs(target string) []engine.CommandSpec {
	// External base64 decode (best-effort). In-process decoding is preferred.
	// Many Kali systems include `base64` coreutils.
	// If target is not base64, command will fail; executor continues.
	if fi, err := os.Stat(target); err == nil && fi.Mode().IsRegular() {
		// In-process crypto runner already tries to decode file contents.
		return []engine.CommandSpec{}
	}
	return []engine.CommandSpec{
		{Name: "base64_decode", Required: false, Command: []string{"bash", "-lc", "printf %s " + shellQuote(target) + " | base64 -d 2>/dev/null || true"}},
	}
}

func pwnSpecs(target string) []engine.CommandSpec {
	// This version avoids network exploitation automation.
	// We still run local binary/security inspection to support CTF workflows.
	// Note: target can be a local file path.
	maybeFile := target
	if maybeFile == "" {
		return []engine.CommandSpec{}
	}
	fi, err := os.Stat(maybeFile)
	if err != nil || !fi.Mode().IsRegular() {
		return []engine.CommandSpec{}
	}
	ext := strings.ToLower(filepath.Ext(target))
	if ext == ".txt" || ext == ".log" || ext == ".md" || ext == ".json" {
		return []engine.CommandSpec{
			{Name: "strings", Required: false, Command: []string{"strings", "-a", "-n", "4", target}},
		}
	}
	// Binary analysis-ish.
	return []engine.CommandSpec{
		{Name: "file_type", Required: false, Command: []string{"file", target}},
		{Name: "checksec", Required: false, Command: []string{"checksec", "--file", target}},
		{Name: "strings", Required: false, Command: []string{"strings", "-a", "-n", "4", target}},
	}
}

func miscSpecs(target string) []engine.CommandSpec {
	// Provide environment info and basic local recon helpers without exploitation.
	// Useful for CTFs where you want to know what you have.
	return []engine.CommandSpec{
		{Name: "id", Required: false, Command: []string{"id"}},
		{Name: "uname", Required: false, Command: []string{"uname", "-a"}},
		{Name: "target_preview", Required: false, Command: []string{"bash", "-lc", "echo " + shellQuote(previewTarget(target))}},
	}
}

func previewTarget(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "(empty)"
	}
	if len(t) > 120 {
		return t[:120] + "..."
	}
	return t
}

// shellQuote returns a POSIX-ish safe single-quoted string for simple shell usage.
func shellQuote(s string) string {
	// Replace ' with '"'"' pattern.
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

