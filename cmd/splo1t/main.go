package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/splo1t/splo1t/internal/engine"
	"github.com/splo1t/splo1t/internal/modules"
	"github.com/splo1t/splo1t/internal/pivot"
	"github.com/splo1t/splo1t/internal/rootcheck"
	"github.com/splo1t/splo1t/internal/ui"
	"github.com/splo1t/splo1t/internal/util"
)

type challengeType string

const (
	chWeb       challengeType = "web"
	chPwn       challengeType = "pwn"
	chReverse   challengeType = "reverse"
	chForensics challengeType = "forensics"
	chCrypto    challengeType = "crypto"
	chMisc      challengeType = "misc"
)

func main() {
	rootcheck.RequireRootOrExit()

	ui.PrintBanner()

	selected, ok := ui.PromptMenu()
	if !ok {
		fmt.Fprintln(os.Stderr, "[-] invalid selection")
		os.Exit(1)
	}

	target := ui.PromptLine("Enter Target:", "(IP / Domain / File / Text)")
	flagRegex := ui.PromptLine("Enter Flag Format (regex):", "")

	runDir, err := util.CreateRunDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] failed to create run directory: %v\n", err)
		os.Exit(1)
	}

	// Flag scanner must start early so it can catch matches from any module.
	flagScanner, err := engine.NewFlagScanner(flagRegex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] invalid regex: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] run directory: %s\n", runDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Resolve which modules to execute based on user selection and target heuristics.
	plan := pivot.ResolvePlan(selected, target)
	if len(plan) == 0 {
		fmt.Println("[-] no applicable module plan resolved")
		os.Exit(1)
	}

	execEngine := engine.NewExecutor(exec.Config{
		MaxConcurrency: 4,
		RunDir:         runDir,
		FlagScanner:    flagScanner,
	})

	start := time.Now()
	var commandErrors int
	for _, mod := range plan {
		commandErrors += modules.RunModule(ctx, mod, target, execEngine)
	}

	_ = flagScanner.FlushFinal()
	fmt.Printf("[+] finished in %s\n", time.Since(start).Round(time.Millisecond))
	fmt.Printf("[+] flags detected: %d\n", flagScanner.Count())
	if commandErrors > 0 {
		fmt.Printf("[!] completed with %d command error(s). Some tools may not be installed.\n", commandErrors)
	}
}

