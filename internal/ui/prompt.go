package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PromptMenu prints the challenge type menu and returns the selected key.
func PromptMenu() (string, bool) {
	fmt.Println("Select Challenge Type:")
	fmt.Println("[1] Web")
	fmt.Println("[2] Pwn")
	fmt.Println("[3] Reverse")
	fmt.Println("[4] Forensics")
	fmt.Println("[5] Crypto")
	fmt.Println("[6] Misc")
	fmt.Print("> ")

	line := readLine()
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		return "", false
	}

	switch n {
	case 1:
		return "web", true
	case 2:
		return "pwn", true
	case 3:
		return "reverse", true
	case 4:
		return "forensics", true
	case 5:
		return "crypto", true
	case 6:
		return "misc", true
	default:
		return "", false
	}
}

func PromptLine(label, hint string) string {
	if hint != "" {
		fmt.Printf("%s %s\n", label, hint)
	} else {
		fmt.Printf("%s\n", label)
	}
	// Minimal prompt styling: user types on the next line.
	return strings.TrimRight(readLine(), "\r\n")
}

func readLine() string {
	in := bufio.NewReader(os.Stdin)
	s, _ := in.ReadString('\n')
	// Allow EOF without newline.
	if len(s) == 0 {
		return ""
	}
	return strings.TrimRight(s, "\r\n")
}

