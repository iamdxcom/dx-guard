#!/usr/bin/env bash
# dx-guard: PreToolUse hook for Claude Code
# Intercepts npm/pip/pnpm/yarn install commands and scans packages via OSV.dev
# Uses hookSpecificOutput with permissionDecision for PreToolUse
# Always exits 0 — decision is controlled via JSON stdout

# Ensure common tool paths are available
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

if [ "$TOOL_NAME" != "Bash" ] || [ -z "$COMMAND" ]; then
  exit 0
fi

# ─── Detect package install commands ───────────────────────────────────────────

ECOSYSTEM=""
PACKAGES=""

# Extract install sub-command from chained commands (&&, ;, ||)
CMD=$(printf '%s' "$COMMAND" | sed 's/&&/\'$'\n''/g' | sed 's/;/\'$'\n''/g' | sed 's/||/\'$'\n''/g' | grep -E '^[[:space:]]*(npm[[:space:]]+(install|i|add)|pnpm[[:space:]]+(add|install|i)|yarn[[:space:]]+add|bun[[:space:]]+(add|install|i)|pip3?[[:space:]]+install|python3?[[:space:]]+-m[[:space:]]+pip[[:space:]]+install|uv[[:space:]]+(pip[[:space:]]+install|add))[[:space:]]+' | head -1 | sed 's/^[[:space:]]*//')

[ -z "$CMD" ] && exit 0

if echo "$CMD" | grep -qE '^npm[[:space:]]+(install|i|add)[[:space:]]+'; then
  ECOSYSTEM="npm"
  PACKAGES=$(echo "$CMD" | sed -E 's/^npm[[:space:]]+(install|i|add)[[:space:]]+//' | tr ' ' '\n' | grep -vE '^-' | grep -vE '^$')
elif echo "$CMD" | grep -qE '^pnpm[[:space:]]+(add|install|i)[[:space:]]+'; then
  ECOSYSTEM="npm"
  PACKAGES=$(echo "$CMD" | sed -E 's/^pnpm[[:space:]]+(add|install|i)[[:space:]]+//' | tr ' ' '\n' | grep -vE '^-' | grep -vE '^$')
elif echo "$CMD" | grep -qE '^yarn[[:space:]]+add[[:space:]]+'; then
  ECOSYSTEM="npm"
  PACKAGES=$(echo "$CMD" | sed -E 's/^yarn[[:space:]]+add[[:space:]]+//' | tr ' ' '\n' | grep -vE '^-' | grep -vE '^$')
elif echo "$CMD" | grep -qE '^bun[[:space:]]+(add|install|i)[[:space:]]+'; then
  ECOSYSTEM="npm"
  PACKAGES=$(echo "$CMD" | sed -E 's/^bun[[:space:]]+(add|install|i)[[:space:]]+//' | tr ' ' '\n' | grep -vE '^-' | grep -vE '^$')
elif echo "$CMD" | grep -qE '^pip3?[[:space:]]+install[[:space:]]+'; then
  ECOSYSTEM="PyPI"
  PACKAGES=$(echo "$CMD" | sed -E 's/^pip3?[[:space:]]+install[[:space:]]+//' | tr ' ' '\n' | grep -vE '^-' | grep -vE '^$')
elif echo "$CMD" | grep -qE '^python3?[[:space:]]+-m[[:space:]]+pip[[:space:]]+install[[:space:]]+'; then
  ECOSYSTEM="PyPI"
  PACKAGES=$(echo "$CMD" | sed -E 's/^python3?[[:space:]]+-m[[:space:]]+pip[[:space:]]+install[[:space:]]+//' | tr ' ' '\n' | grep -vE '^-' | grep -vE '^$')
elif echo "$CMD" | grep -qE '^uv[[:space:]]+(pip[[:space:]]+install|add)[[:space:]]+'; then
  ECOSYSTEM="PyPI"
  PACKAGES=$(echo "$CMD" | sed -E 's/^uv[[:space:]]+(pip[[:space:]]+install|add)[[:space:]]+//' | tr ' ' '\n' | grep -vE '^-' | grep -vE '^$')
else
  exit 0
fi

[ -z "$PACKAGES" ] && exit 0

# ─── Scan packages via OSV.dev ─────────────────────────────────────────────────

HAS_MALICIOUS=false
HAS_VULNS=false
RESULT=""

for PKG_RAW in $PACKAGES; do
  PKG_NAME=$(echo "$PKG_RAW" | sed -E 's/[@>=<~^].*//')
  PKG_VERSION=""
  if echo "$PKG_RAW" | grep -qE '^@[^/]+/[^@]+'; then
    PKG_NAME=$(echo "$PKG_RAW" | sed -E 's/(@[^/]+\/[^@]+).*/\1/')
    # Extract version from scoped package: @scope/name@version
    PKG_VERSION=$(echo "$PKG_RAW" | sed -E 's/@[^/]+\/[^@]+//' | sed -E 's/^@//')
  else
    # Extract version from unscoped package: name@version
    PKG_VERSION=$(echo "$PKG_RAW" | sed -n 's/^[^@]*@//p')
  fi
  [ -z "$PKG_NAME" ] && continue

  RESPONSE=$(curl -s --max-time 5 -X POST "https://api.osv.dev/v1/query" \
    -H "Content-Type: application/json" \
    -d "{\"package\":{\"name\":\"$PKG_NAME\",\"ecosystem\":\"$ECOSYSTEM\"}}" 2>/dev/null) || RESPONSE='{}'

  VULN_COUNT=$(echo "$RESPONSE" | jq '[.vulns // [] | .[]] | length' 2>/dev/null) || VULN_COUNT=0
  if [ "$VULN_COUNT" = "0" ] || [ -z "$VULN_COUNT" ]; then
    RESULT="${RESULT}✅ ${PKG_NAME} — clean\n"
    continue
  fi

  IS_MAL=$(echo "$RESPONSE" | jq '[.vulns[]? | select((.summary // "" | ascii_downcase | startswith("malicious")) or (.database_specific // {} | has("malicious-packages-origins")))] | length' 2>/dev/null) || IS_MAL=0

  if [ "$IS_MAL" -gt 0 ]; then
    MAL_VERSIONS=$(echo "$RESPONSE" | jq -r '[.vulns[]? | select((.summary // "" | ascii_downcase | startswith("malicious")) or (.database_specific // {} | has("malicious-packages-origins"))) | .affected[]?.versions[]?] | unique | join(", ")' 2>/dev/null) || MAL_VERSIONS=""

    # If a specific version is pinned, check if it's actually in the malicious list
    if [ -n "$PKG_VERSION" ]; then
      IS_PINNED_MAL=$(echo "$RESPONSE" | jq --arg v "$PKG_VERSION" '[.vulns[]? | select((.summary // "" | ascii_downcase | startswith("malicious")) or (.database_specific // {} | has("malicious-packages-origins"))) | .affected[]?.versions[]?] | unique | map(select(. == $v)) | length' 2>/dev/null) || IS_PINNED_MAL=0
      if [ "$IS_PINNED_MAL" = "0" ] || [ -z "$IS_PINNED_MAL" ]; then
        RESULT="${RESULT}✅ ${PKG_NAME}@${PKG_VERSION} — pinned safe version (malicious: ${MAL_VERSIONS})\n"
        continue
      fi
    fi

    HAS_MALICIOUS=true
    # Get latest safe version from registry
    if [ "$ECOSYSTEM" = "npm" ]; then
      LATEST=$(curl -s --max-time 3 "https://registry.npmjs.org/$PKG_NAME/latest" 2>/dev/null | jq -r '.version // empty' 2>/dev/null) || LATEST=""
    else
      LATEST=$(curl -s --max-time 3 "https://pypi.org/pypi/$PKG_NAME/json" 2>/dev/null | jq -r '.info.version // empty' 2>/dev/null) || LATEST=""
    fi
    RESULT="${RESULT}🚨 ${PKG_NAME} — MALICIOUS versions: ${MAL_VERSIONS}\n"
    if [ -n "$LATEST" ]; then
      RESULT="${RESULT}   Safe version: ${PKG_NAME}@${LATEST}\n"
    fi
    continue
  fi

  HAS_VULNS=true
  VULN_LINES=$(echo "$RESPONSE" | jq -r '[.vulns[:5][] | (.id) + " | " + (.database_specific.severity // "UNKNOWN") + " | " + ((.summary // "-") | .[0:50]) + " | " + ([.affected[]?.ranges[]?.events[]? | select(.fixed) | .fixed] | first // "-")] | .[]' 2>/dev/null) || VULN_LINES=""

  RESULT="${RESULT}⚠️  ${PKG_NAME} — ${VULN_COUNT} vulnerabilities:\nID | Severity | Summary | Fixed\n${VULN_LINES}\n"
done

# ─── Output ────────────────────────────────────────────────────────────────────

OUTPUT=$(printf '%b' "$RESULT")

if [ "$HAS_MALICIOUS" = true ]; then
  echo "$OUTPUT" >&2
  jq -nc --arg r "$OUTPUT" '{
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": $r
    }
  }'
  exit 0
elif [ "$HAS_VULNS" = true ]; then
  echo "$OUTPUT" >&2
  jq -nc --arg r "$OUTPUT" '{
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "ask",
      "permissionDecisionReason": $r
    }
  }'
  exit 0
else
  exit 0
fi
