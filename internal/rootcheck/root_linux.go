//go:build linux

package rootcheck

import (
	"fmt"
	"os"
)

// RequireRootOrExit enforces the runtime "sudo splo1t" requirement.
func RequireRootOrExit() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "[-] you do not have permissions")
		os.Exit(1)
	}
}

