#!/usr/bin/env bash
#
# review-pkgbuild.sh — scan a PKGBUILD / *.install / .SRCINFO for high-risk
# supply-chain markers before a build is allowed to run.
#
# This is the PERMANENT, campaign-agnostic defense: it does not rely on any
# "known-bad package" list. It flags the patterns that supply-chain attacks
# use to execute code at build/install time.
#
# Usage:
#   review-pkgbuild.sh <dir-or-file> [<dir-or-file> ...]
#   review-pkgbuild.sh ~/.cache/pikaur/build/somepkg
#
# Exit codes:
#   0 = no markers
#   1 = only informational markers (network fetches in build) — eyeball it
#   2 = HIGH-risk markers found (JS package pulls, IOC names, pipe-to-shell,
#       eval/base64, unexpected install scriptlets) — DO NOT build unreviewed
set -uo pipefail

[[ $# -eq 0 ]] && { echo "usage: $0 <dir-or-file> [...]" >&2; exit 64; }

# HIGH-risk: code execution / dependency injection vectors
HIGH='(\bnpm\b|\bnpx\b|\bpnpm\b|\byarn\b|\bbun\b|\bbunx\b|atomic-lockfile|js-digest|src/hooks/deps|base64[[:space:]]+-d|[[:space:]]eval[[:space:]]|\|[[:space:]]*(ba)?sh\b|curl[^|]*\|[[:space:]]*(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh)'
# install scriptlets — legitimate sometimes, but always worth a human look,
# especially on -bin packages that should only drop a prebuilt binary
HOOKS='^[[:space:]]*(pre|post)_(install|upgrade|remove)[[:space:]]*\(\)'
# informational: any network fetch inside the recipe
INFO='(\bcurl\b|\bwget\b|\bgit clone\b)'

collect() {
  local t=$1
  if [[ -f "$t" ]]; then printf '%s\n' "$t"; return; fi
  find "$t" -maxdepth 3 \( -name PKGBUILD -o -name '*.install' -o -name '.SRCINFO' \) 2>/dev/null
}

files=()
for arg in "$@"; do
  while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(collect "$arg")
done

if [[ ${#files[@]} -eq 0 ]]; then
  echo "No PKGBUILD/.install/.SRCINFO found under: $*" >&2
  exit 64
fi

rc=0
high_hits=0
for f in "${files[@]}"; do
  h=$(grep -nEi "$HIGH" "$f" 2>/dev/null || true)
  k=$(grep -nE  "$HOOKS" "$f" 2>/dev/null || true)
  i=$(grep -nEi "$INFO"  "$f" 2>/dev/null || true)
  [[ -z "$h$k$i" ]] && continue
  echo "### $f"
  if [[ -n "$h" ]]; then echo "  [HIGH] code-exec / dependency-injection markers:"; sed 's/^/    /' <<<"$h"; high_hits=1; fi
  if [[ -n "$k" ]]; then echo "  [HOOK] install scriptlet present (review intent):";  sed 's/^/    /' <<<"$k"; [[ $rc -lt 1 ]] && rc=1; fi
  if [[ -n "$i" ]]; then echo "  [info] network fetch in recipe:";                    sed 's/^/    /' <<<"$i"; [[ $rc -lt 1 ]] && rc=1; fi
  echo
done

[[ $high_hits -eq 1 ]] && rc=2

case $rc in
  0) echo "review-pkgbuild: clean — no markers in ${#files[@]} file(s)." ;;
  1) echo "review-pkgbuild: informational markers only — eyeball the lines above." ;;
  2) echo "review-pkgbuild: HIGH-RISK markers found — do NOT build until a human clears them." ;;
esac
exit $rc
