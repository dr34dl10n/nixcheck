---
name: nixcheck
description: Linux system health check — diagnose services, resources, logs, JVM, and security issues with one command.
version: 1.0.0
author: dr34dl10n
license: MIT
repository: https://github.com/dr34dl10n/nixcheck
tags: [linux, devops, health-check, monitoring, security, jvm, systemd]
---

# nixcheck — Linux System Health Check

Run `nixcheck` to perform a comprehensive health check on the current Linux machine. Checks services, containers, resources (CPU/RAM/disk), log errors, JVM configs, and security issues — all 100% deterministic, no LLM calls needed.

## Setup

nixcheck must be installed before use. Run this once:

```bash
if [ ! -d "$HOME/.local/share/nixcheck/.venv" ]; then
  git clone https://github.com/dr34dl10n/nixcheck.git "$HOME/.local/share/nixcheck" 2>/dev/null || git -C "$HOME/.local/share/nixcheck" pull
  python3 -m venv "$HOME/.local/share/nixcheck/.venv"
  "$HOME/.local/share/nixcheck/.venv/bin/pip" install -e "$HOME/.local/share/nixcheck" -q
fi
```

Binary path after install: `~/.local/share/nixcheck/.venv/bin/nixcheck`

Verify with: `~/.local/share/nixcheck/.venv/bin/nixcheck --version` or `nixcheck --json --fast`

## Usage Patterns

### Quick health check (for agent analysis)

Always use `--json --fast` for agent consumption — fast and structured:

```bash
~/.local/share/nixcheck/.venv/bin/nixcheck --json --fast
```

Exit codes: **0** = healthy, **1** = execution error, **2** = problems detected (critical logs or security issues).

### Human-readable report

```bash
~/.local/share/nixcheck/.venv/bin/nixcheck --fast
```

### Targeted checks

```bash
nixcheck --json --fast --no-containers   # Skip Docker/Podman
nixcheck --json --fast --no-security     # Skip security checks
nixcheck --json --fast --threshold 90    # Warn only above 90%
nixcheck --json --fast --log-lines 500   # Analyze last 500 log lines
nixcheck --json --fast --miner-list /etc/nixcheck/miners.yaml  # Custom miner list
```

### Full diagnostic (slower, accurate CPU)

```bash
nixcheck --json    # Without --fast, blocks briefly for CPU measurement
```

### Quiet summary (one line)

```bash
nixcheck --fast --quiet
```

## JSON Output Structure

```json
{
  "hostname": "prod-server",
  "services_count": 29,
  "containers_count": 3,
  "resources": {
    "cpu_percent": 45.2,
    "memory_percent": 72.0,
    "disk_percent": 88.5
  },
  "errors_count": 14,
  "java_detected": true,
  "jvm_configs_count": 2,
  "security_issues_count": 1,
  "has_warnings": true
}
```

## When to Use

- User asks "what's wrong with this server" or "check system health"
- Before/after deployments to verify system state
- Investigating performance issues (CPU, RAM, disk, swap)
- Checking for security concerns (crypto miners, suspicious crons)
- Diagnosing Java/JVM heap configuration issues
- Incident response or on-call triage
- Cron-scheduled health monitoring

## How to Interpret and Report

1. Run `nixcheck --json --fast` via `terminal()`
2. Parse the JSON output
3. Analyze the key indicators:
   - `errors_count > 0` → log errors detected; run `nixcheck` without `--json` for full error details, or `nixcheck --fast --verbose` for debug-level logs
   - `resources.cpu_percent > threshold` → high CPU
   - `resources.memory_percent > threshold` → high RAM usage
   - `resources.disk_percent > threshold` → disk filling up
   - `security_issues_count > 0` → investigate security issues
   - `java_detected == true && jvm_configs_count > 0` → check JVM heap settings
4. **Always present a diagnosis and recommendations** to the user — not just raw data
5. If `has_warnings` is false, confirm the system looks healthy

For detailed error/source breakdown, run the full rich report:
```bash
~/.local/share/nixcheck/.venv/bin/nixcheck --fast 2>/dev/null
```

## Programmatic Python Usage

For advanced scenarios, nixcheck can also be invoked as a Python library:

```python
import json
from nixcheck.graph import run_nixcheck
from nixcheck.reporter import generate_json_summary
from nixcheck.models import NixCheckState

result = run_nixcheck(fast_mode=True)
state = NixCheckState(**result) if isinstance(result, dict) else result
summary = generate_json_summary(state)
```

Requires the nixcheck venv Python: `~/.local/share/nixcheck/.venv/bin/python`

## What nixcheck Checks

| Category | What's verified |
|---|---|
| **Services** | Active systemd services, PID, memory, CPU (top 15) |
| **Containers** | Docker and Podman — auto-detection, IDs |
| **Resources** | CPU, RAM, disk (`/`), load average, swap — configurable thresholds |
| **Logs** | `journalctl` errors + `/var/log/*`, sorted by severity |
| **JVM** | Java processes detected, Heap `-Xmx`/`-Xms`, recommendations |
| **Security** | Crypto miners, high-CPU processes, suspicious crons (`curl|bash`, `base64 -d`) |

No root required — nixcheck works as a regular user. Root access only needed for `/var/log/syslog`, `/var/log/kern.log`, and `/var/spool/cron/` (nixcheck degrades gracefully without).

## Pitfalls

- **Exit code 2 means issues detected** — this is normal when the machine has log errors; don't treat it as a tool failure
- **`--fast` skips blocking CPU measurement** — CPU% will be less accurate but the check completes instantly. Use without `--fast` only when precise CPU measurement matters
- **No root needed** — works as regular user; `/var/log/syslog` and `/var/spool/cron/` require root but nixcheck degrades gracefully
- **Rich output is verbose** — for agent analysis, always use `--json`; Rich tables are for human consumption
- **`--quiet` mode** — one-line summary, good for cron jobs or quick checks