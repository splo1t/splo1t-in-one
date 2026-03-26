//go:build !linux

package rootcheck

// RequireRootOrExit is a no-op for non-Linux builds.
// The intended target for this tool is Kali Linux (Linux).
func RequireRootOrExit() {}

