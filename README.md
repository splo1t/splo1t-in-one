# SPLO1T

`SPLO1T` is a Linux CLI framework for automating common CTF workflows and local binary/forensics/crypto analysis. It provides:

- An interactive menu
- Streaming output capture from external tools
- A regex-based flag scanner that detects and prints flags immediately
- A pivot engine that auto-selects the best module based on the target you provide

## Features

- Root-required startup (`sudo splo1t`)
- Interactive menu:
  - `[1] Web`
  - `[2] Pwn`
  - `[3] Reverse`
  - `[4] Forensics`
  - `[5] Crypto`
  - `[6] Misc`
- Prompts:
  - `Enter Target: (IP / Domain / File / Text)`
  - `Enter Flag Format (regex):`
- Executes installed Kali utilities via system calls (when present in `PATH`)
- Continuous regex scanning across stdout/stderr while commands run
- Graceful error handling: missing tools are skipped, failures are logged, execution continues
- Parallel command execution inside a module (bounded concurrency)

## Requirements

### System

- Kali Linux (tool intended for Linux)
- `sudo` available
- `go` (used to build from source during installation)

### Optional Kali tools (used when installed)

The tool will skip commands whose binaries are not found. Recommended packages include:

- Reverse / binary inspection:
  - `file`, `strings`, `readelf`
  - `checksec` (optional, from `checksec` package)
- Forensics:
  - `binwalk`, `exiftool` (from `libimage-exiftool-perl`)
  - `file`
- Web (lightweight):
  - `curl` (to fetch URL content for flag scanning)
- Crypto:
  - No external crypto tools are required (decoding is also done in-process)

### Important Scope Note

This repository version is intentionally focused on CTF-style workflows and local analysis (forensics/reverse/crypto) plus lightweight HTTP fetching for the `Web` module. It does *not* embed exploitation automation for network services (for example `metasploit`, `hydra`, `sqlmap`, `dalfox`, or `searchsploit`), even if those tools are available on Kali. You can extend the module command specs yourself in authorized environments.

## Installation (Kali)

### 1. Clone

```bash
cd ~
git clone https://github.com/<your-username>/splo1t.git
cd splo1t
```

### 2. Make installer executable

```bash
chmod +x installer/install.sh
```

### 3. Install system-wide

```bash
sudo ./installer/install.sh
```

This places the binary at:

- `/usr/local/bin/splo1t`

### Verify

```bash
which splo1t
ls -l /usr/local/bin/splo1t
```

## Usage

Run with root:

```bash
sudo splo1t
```

Or if you are already root:

```bash
splo1t
```

If you run it without root, it exits with:

```text
[-] you do not have permissions
```

## Example run

Scan a local file and extract flags:

```bash
sudo splo1t
```

Then input:

- Select Challenge Type: `4` (Forensics)
- Enter Target: `/path/to/challenge.bin`
- Enter Flag Format (regex): `flag\{[^}]+\}`

`SPLO1T` will run available local inspection commands (e.g., `file`, `exiftool`, `binwalk` when installed), continuously scan their output, and print detected flags as soon as they appear.

## Notes on extending modules

`SPLO1T` is designed to be extensible: modules are implemented as command specs in the codebase and are skipped if the tool is missing.

If you want to add more tooling, create a new module function and return `engine.CommandSpec` entries in `internal/modules/modules.go`, then wire it into the pivot logic in `internal/pivot/pivot.go`.

