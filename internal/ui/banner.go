package ui

import "fmt"

// PrintBanner renders the ASCII hacker banner.
func PrintBanner() {
	// ANSI colors; works in most terminals.
	const cyan = "\033[36m"
	const green = "\033[32m"
	const bold = "\033[1m"
	const reset = "\033[0m"

	// ASCII art banner (kept intentionally compact for terminals).
	banner := []string{
		"   ____   _____   ______   ______",
		"  / __ \\ / ___/  / ____/  / ____/ ",
		" / /_/ // /__   / /__    / __/    ",
		"/ _, _// __/  / ___/   / /___    ",
		"/_/ |_|/_/    /_/      /_____/   ",
		"",
		"SPLO1T",
	}

	for _, line := range banner {
		if line == "SPLO1T" {
			fmt.Printf("%s%s%s\n", bold+green, line, reset)
		} else {
			fmt.Printf("%s%s%s\n", bold+cyan, line, reset)
		}
	}
	fmt.Printf("%s%s\n\n", cyan, "CTF workflows and local analysis automation")
}

