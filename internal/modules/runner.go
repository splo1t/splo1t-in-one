package modules

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/splo1t/splo1t/internal/engine"
	"github.com/splo1t/splo1t/internal/modules/safecrypto"
)

// RunModule executes a module. It may include in-process analysis (crypto decoding)
// and external tool execution via the engine.
func RunModule(ctx context.Context, mod string, target string, exec *engine.Executor) int {
	mod = strings.ToLower(strings.TrimSpace(mod))
	switch mod {
	case "crypto":
		runCryptoInProcess(ctx, target, exec)
		specs := ModuleCommandSpecs(mod, target)
		return exec.RunModule(ctx, mod, specs)
	default:
		specs := ModuleCommandSpecs(mod, target)
		return exec.RunModule(ctx, mod, specs)
	}
}

func runCryptoInProcess(ctx context.Context, target string, exec *engine.Executor) {
	_ = ctx
	s := strings.TrimSpace(target)
	if s == "" {
		return
	}

	// Attempt to decode user-supplied text (base64/hex/url/rot13).
	decoded := safecrypto.TryDecodeAll(s)
	if len(decoded) == 0 {
		// If it's a file, attempt to treat file content as encoded.
		if fi, err := os.Stat(s); err == nil && fi.Mode().IsRegular() {
			b, err := safecrypto.ReadLimited(s, 2*1024*1024)
			if err == nil {
				decoded = safecrypto.TryDecodeAll(string(b))
			}
		}
	}

	if len(decoded) == 0 {
		return
	}

	fmt.Printf("[+] crypto: attempting %d decode(s)\n", len(decoded))
	for i, d := range decoded {
		// Scan decoded output immediately so flags can be detected.
		exec.Scanner().Consume(d.Bytes)
		// Persist some decode artifacts for inspection.
		_ = safecrypto.WriteDecodeArtifact(exec.RunDir(), "crypto_decode_"+fmt.Sprint(i), d.Name, string(d.Bytes))
	}
}

