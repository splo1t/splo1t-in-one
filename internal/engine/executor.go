package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type Config struct {
	MaxConcurrency int
	RunDir         string
	FlagScanner    *FlagScanner
}

type Executor struct {
	maxConc int
	runDir  string
	scanner *FlagScanner
	sem     chan struct{}
}

func NewExecutor(cfg Config) *Executor {
	maxc := cfg.MaxConcurrency
	if maxc <= 0 {
		maxc = 4
	}
	return &Executor{
		maxConc: maxc,
		runDir:  cfg.RunDir,
		scanner: cfg.FlagScanner,
		sem:     make(chan struct{}, maxc),
	}
}

func (e *Executor) Scanner() *FlagScanner { return e.scanner }
func (e *Executor) RunDir() string       { return e.runDir }

type CommandSpec struct {
	Name    string
	Command []string // argv[0] is the command
	// If false, missing command will not error; it will be skipped.
	Required bool
	// If true, output is logged but no command output is scanned for flags.
	DisableFlagScan bool
}

type ModuleName string

func (e *Executor) RunModule(ctx context.Context, module string, specs []CommandSpec) int {
	fmt.Printf("\n[+] module: %s\n", module)
	var wg sync.WaitGroup
	var cmdErrors int
	var errMu sync.Mutex

	for _, spec := range specs {
		wg.Add(1)
		go func(s CommandSpec) {
			defer wg.Done()
			if err := e.runCommand(ctx, module, s); err != nil {
				errMu.Lock()
				cmdErrors++
				errMu.Unlock()
			}
		}(spec)
	}

	wg.Wait()
	return cmdErrors
}

type scannerWriter struct {
	scanner *FlagScanner
	enabled bool
}

func (w scannerWriter) Write(p []byte) (int, error) {
	if w.enabled && w.scanner != nil {
		w.scanner.Consume(p)
	}
	return len(p), nil
}

func (e *Executor) runCommand(ctx context.Context, module string, spec CommandSpec) error {
	// Concurrency limiter.
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	if len(spec.Command) == 0 {
		return fmt.Errorf("empty command spec for %q", spec.Name)
	}

	argv := append([]string{}, spec.Command...)
	cmdName := argv[0]
	toolPath, err := exec.LookPath(cmdName)
	if err != nil {
		if spec.Required {
			return fmt.Errorf("required tool not found: %s", cmdName)
		}
		fmt.Printf("[!] skipping (missing): %s\n", cmdName)
		return nil
	}
	argv[0] = toolPath

	fmt.Printf("[+] running: %s\n", strings.Join(argv, " "))

	stdoutLogPath := filepath.Join(e.runDir, fmt.Sprintf("%s__%s__stdout.log", sanitize(module), sanitize(spec.Name)))
	stderrLogPath := filepath.Join(e.runDir, fmt.Sprintf("%s__%s__stderr.log", sanitize(module), sanitize(spec.Name)))
	stdoutLogFile, err := os.Create(stdoutLogPath)
	if err != nil {
		return fmt.Errorf("failed to create stdout log file: %w", err)
	}
	defer stdoutLogFile.Close()
	stderrLogFile, err := os.Create(stderrLogPath)
	if err != nil {
		return fmt.Errorf("failed to create stderr log file: %w", err)
	}
	defer stderrLogFile.Close()

	disableScan := spec.DisableFlagScan
	swriter := scannerWriter{
		scanner: e.scanner,
		enabled: !disableScan,
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	// Stream stdout and stderr simultaneously.
	var streamWg sync.WaitGroup
	streamWg.Add(2)

	go func() {
		defer streamWg.Done()
		// Copy in chunks; each write triggers scanner Consume().
		_, _ = io.Copy(io.MultiWriter(stdoutLogFile, swriter), bufio.NewReader(stdout))
	}()
	go func() {
		defer streamWg.Done()
		_, _ = io.Copy(io.MultiWriter(stderrLogFile, swriter), bufio.NewReader(stderr))
	}()

	streamWg.Wait()
	err = cmd.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] command failed (%s): %v\n", spec.Name, err)
		// Still return error so caller can track.
		return err
	}
	return nil
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}

