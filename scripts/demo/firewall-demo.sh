#!/usr/bin/env bash
#
# firewall-demo.sh — see what a tightly-scoped token still can't do, live, in
# ~10 seconds.
#
# Everyone's first objection to Grenz is "why not just scope the GitHub token?"
# A repo-scoped token still merges a PR the instant an agent is told to, is the
# agent's to leak, and can only be killed by regenerating it at GitHub. This demo
# spins up a throwaway Grenz on loopback and shows two things scoping can't give
# you: an in-scope action (pr:merge) HELD for a human who denies it, and an
# operator revoke that cuts the agent off in one word without any GitHub round-trip.
#
# NO real credentials: the github upstream points at a dummy value, and every
# decision is read from the `x-grenz-decision` / `x-grenz-reason` response
# headers, so nothing needs to reach a real API.
#
# Requires: bun (to compile the binary), curl. Runs entirely on 127.0.0.1.
# Override the port with PORT=NNNN if 8787 is busy (e.g. a real proxy running).
#
set -u  # best-effort demo: a single failed request should not abort the story

PORT="${PORT:-8787}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="$(cd "$HERE/../../proxy" && pwd)"
BIN="$PROXY_DIR/dist/grenz"
B="http://127.0.0.1:$PORT"

cd "$PROXY_DIR"
echo "  building the grenz binary..."
bun build ./src/index.ts --compile --outfile "$BIN" >/dev/null 2>&1 \
  || { echo "  build failed — is bun installed?"; exit 1; }
[ -x "$BIN" ] || { echo "  no binary at $BIN"; exit 1; }

HOME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/grenz-demo-XXXXXX")"
HDR="$HOME_DIR/headers.txt"
RUN_PID=""
cleanup() {
  [ -n "$RUN_PID" ] && kill "$RUN_PID" 2>/dev/null
  rm -rf "$HOME_DIR"
}
trap cleanup EXIT

# 1) Scaffold a home and stash a (fake) credential in the vault.
#    init prints the GRENZ_TOKEN once, to stdout — capture it there.
INIT_OUT="$("$BIN" init --home "$HOME_DIR" 2>&1)"
GTOK="$(printf %s "$INIT_OUT" | grep -m1 -oE 'grenz_[A-Za-z0-9_-]+')"
printf %s "dummy-not-a-real-token" | "$BIN" vault set github_token --home "$HOME_DIR" >/dev/null 2>&1

# 2) A realistic policy: reads flow, but merging a PR — something a repo-scoped
#    PAT is perfectly allowed to do — is HELD for a human.
cat > "$HOME_DIR/policy.yaml" <<'YAML'
agent: claude-code
on_behalf_of: demo@grenz.dev
grants:
  - tool: github
    allow:
      - repo:read
      - pr:read
    require_approval:
      - pr:merge
YAML

"$BIN" run --home "$HOME_DIR" --port "$PORT" >/dev/null 2>&1 &
RUN_PID=$!
sleep 2

# act METHOD PATH LABEL — print the firewall's decision for one request.
act() {
  curl -s -o /dev/null -D "$HDR" -X "$1" -H "Authorization: Bearer $GTOK" "$B$2" || true
  render "$3"
}
render() {
  local dec rea
  dec="$(grep -i '^x-grenz-decision:' "$HDR" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)"
  rea="$(grep -i '^x-grenz-reason:' "$HDR" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)"
  printf '  %-38s %-6s %s\n' "$1" "${dec:-?}" "${rea:-}"
}

echo ""
echo "  Grenz - what a scoped token still can't do."
echo "  ==========================================="
echo "  WHAT THE AGENT TRIES                   VERDICT WHY"

act GET "/u/github/repos/o/r" "read a repo (its real job)"

# merge a PR: in-scope for a PAT, HELD here. Fire it in the background (it blocks
# on approval), then the "operator" denies the pending request from the CLI.
# --port targets the admin API at THIS demo's proxy (the home's grenz.yaml still
# names the default port, so without it the CLI would query the wrong proxy).
curl -s --max-time 20 -o /dev/null -D "$HDR" -X PUT -H "Authorization: Bearer $GTOK" \
  "$B/u/github/repos/o/r/pulls/1/merge" &
MERGE_JOB=$!
APR=""
for _ in $(seq 1 100); do
  APR="$("$BIN" approvals --home "$HOME_DIR" --port "$PORT" 2>/dev/null | grep -m1 -oE 'apr_[A-Za-z0-9]+' || true)"
  [ -n "$APR" ] && break
  sleep 0.1
done
[ -n "$APR" ] && "$BIN" deny "$APR" --home "$HOME_DIR" --port "$PORT" >/dev/null 2>&1
wait "$MERGE_JOB" 2>/dev/null || true
render "merge a PR (a scoped PAT just does)"

# The operator revoke is the ONLY thing that cuts the agent off here — so the
# token_revoked below genuinely proves the revoke. --port targets THIS demo's
# proxy admin API (the home's grenz.yaml names the default port).
"$BIN" revoke claude-code --home "$HOME_DIR" --port "$PORT" --reason "operator cut it off" >/dev/null 2>&1
echo "  -- you revoke the agent — one command, no GitHub round-trip --"
act GET "/u/github/repos/o/r" "read a repo"

echo ""
echo "  A tightly-scoped token would have merged that PR and kept working. Behind"
echo "  Grenz the merge waited for your yes, the agent never held the real"
echo "  credential, and one 'grenz revoke' cut it off without touching GitHub."
echo ""
