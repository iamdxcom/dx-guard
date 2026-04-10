---
name: scan
description: Scans all project dependencies for known security vulnerabilities using OSV.dev. Reads package.json, requirements.txt, or pyproject.toml and checks every dependency.
---

## CRITICAL RULES
- **NEVER run `npm install`, `pip install`, or any install command.** This skill does NOT install anything.
- **NEVER trigger the hook.** The hook is separate — it runs automatically on real installs.
- You MUST read the dependency file and call the OSV.dev batch API directly with curl.

## Step 1: Read dependencies

Read the dependency file with `cat`:
- `package.json` → extract all package names from `dependencies` and `devDependencies` using jq
- `requirements.txt` → extract package names (strip version specifiers)
- `pyproject.toml` → extract from `[project.dependencies]`

Example for package.json:
```bash
cat package.json | jq -r '[.dependencies // {}, .devDependencies // {}] | map(keys) | flatten | .[]'
```

## Step 2: Query OSV.dev batch API

Build a SINGLE batch query with ALL packages and run it:

```bash
# Build queries JSON from package list
PKGS=$(cat package.json | jq -r '[.dependencies // {}, .devDependencies // {}] | map(keys) | flatten | .[]')
QUERIES=$(echo "$PKGS" | jq -R '{"package":{"name":.,"ecosystem":"npm"}}' | jq -s '{"queries":.}')
curl -s -X POST "https://api.osv.dev/v1/querybatch" -H "Content-Type: application/json" -d "$QUERIES"
```

For PyPI, change `"ecosystem":"npm"` to `"ecosystem":"PyPI"`.

## Step 3: Parse and display results

The response format is `{"results":[{"vulns":[...]},{"vulns":[]},...]}`  — each entry maps to the package at the same index.

Show a markdown table:

| Package | Status | Details |
|---------|--------|---------|
| express | ✅ Clean | |
| axios | 🚨 MALICIOUS | Affected: 1.7.1-1.8.1 → Safe: axios@1.15.0 |
| lodash | ⚠️ 3 vulns | CVE-xxx (HIGH), CVE-yyy (MEDIUM) |

For malicious packages, fetch latest safe version:
- npm: `curl -s https://registry.npmjs.org/PACKAGE/latest | jq -r .version`
- PyPI: `curl -s https://pypi.org/pypi/PACKAGE/json | jq -r .info.version`

## Step 4: Summary

End with: **"X clean, Y vulnerable, Z malicious out of N total packages"**

## Monorepo support
If there are multiple package.json files (e.g. frontend/, backend/), scan each one separately and show results grouped by directory.
