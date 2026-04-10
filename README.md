# 🛡️ dx-guard

**Dependency security guard for AI coding agents.**

dx-guard automatically scans npm and Python packages for known vulnerabilities before your AI coding agent installs them. Zero config. Zero API keys. Powered by [OSV.dev](https://osv.dev).

## Why?

AI coding agents (Claude Code, Cursor, Copilot) install packages autonomously. When a vibecoder says "build me a todo app", the agent pulls in 15+ dependencies without human review. Supply chain attacks like the [Axios compromise (March 2026)](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package) show how dangerous this can be.

dx-guard adds a security checkpoint before every install — automatically.

## How it works

```
You: "build me a chat app"
Claude: npm install express socket.io ...

[dx-guard] 🔍 Scanning dependencies...
[dx-guard] ✅ express — clean
[dx-guard] ⚠️  socket.io — 2 known vulnerabilities [GHSA-xxxx, GHSA-yyyy]
[dx-guard] ⚡ Proceeding — review the warnings above.
```

For **malicious packages**, dx-guard blocks the install entirely:

```
[dx-guard] 🚨 MALICIOUS: evil-package — known malicious package!
[dx-guard] ❌ Install BLOCKED.
```

## Install

### Claude Code Plugin (recommended)

Run these three commands inside Claude Code:

```
/plugin marketplace add iamdxcom/dx-guard
/plugin install dx-guard@iamdxcom-dx-guard
/reload-plugins
```

That's it. dx-guard is now active for all Claude Code sessions.

> **Note:** Once dx-guard is published to the official Claude plugin store, you'll be able to install it with a single command: `claude plugin add dx-guard`

### Manual setup

Copy `hooks/scan.sh` to your project and add to your agent's hook config:

**Claude Code** (`.claude/settings.json`):
```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "./hooks/scan.sh",
        "timeout": 15
      }]
    }]
  }
}
```

## Features

- **Pre-install scanning** — checks packages BEFORE they're installed
- **Multi-ecosystem** — npm, pnpm, yarn, bun, pip, uv
- **Malicious package detection** — blocks known malware
- **Vulnerability reporting** — warns about known CVEs
- **Zero config** — no API keys, no accounts, no setup
- **Fast** — parallel OSV.dev queries, 15s timeout
- **Non-blocking for clean packages** — zero overhead when everything is safe

## Slash Commands

| Command | Description |
|---------|-------------|
| `/dx-guard:scan` | Scan current project's dependencies |

## Requirements

- `bash`, `curl`, `jq` (available on most systems)
- Internet access (to query OSV.dev)

## Data Source

dx-guard uses [OSV.dev](https://osv.dev), Google's open-source vulnerability database that aggregates data from GitHub Security Advisories, PyPA, NVD, and more. No API key required. No rate limits.

## Roadmap

- [ ] Typosquatting detection (Levenshtein distance)
- [ ] Package age check (block recently published packages)
- [ ] Cursor / Windsurf / Copilot plugin packaging  
- [ ] Dashboard at iamdx.com
- [ ] Team policy engine

## License

MIT

## Author

[Onur Erkan](https://iamdx.com)
