#!/usr/bin/env bash
#
# review-pkgbuild.sh — ADVISORY scanner for a PKGBUILD / *.install / .SRCINFO.
#
# IMPORTANT: this is a HINT for a human reviewer, NOT a gate. A PKGBUILD is
# arbitrary bash sourced by makepkg; no regex can prove it safe. Trivial
# obfuscation (variable indirection, hex, base64) defeats any pattern matcher.
# A "clean" result means "no obvious markers" — you must still read the diff.
# It does NOT scan fetched sources (source=()) — upstream build hooks run too.
#
# Usage:
#   review-pkgbuild.sh <dir-or-file> [<dir-or-file> ...]
#
# Exit codes:
#   0 = no markers found (NOT a guarantee — read the recipe)
#   1 = REVIEW: runs a toolchain/interpreter, fetches, obfuscates, adds an
#       install hook, or skips checksums — legitimate sometimes; eyeball it
#   2 = HIGH: known IOC string, pipe-to-interpreter, eval, base64-decode,
#       /dev/tcp, process-substitution exec, or a NUL byte — do NOT build
#       unreviewed
#  64 = could not scan (no recipe found / bad usage) — treat as "unknown", NOT safe
set -uo pipefail

[[ $# -eq 0 ]] && { echo "usage: $0 <dir-or-file> [...]" >&2; exit 64; }

# --- HIGH: near-unambiguous code-exec / payload-staging / known IOCs --------
# (grep -E, case-insensitive). Pipe-to-interpreter matches full paths and
# alternate shells/interpreters; the eval clause matches at column 0 too; base64
# decode in any flag form; source/'.' of a process substitution.
EV='ev''al'   # split literal to avoid naive eval() source scanners; matches the keyword
HIGH='atomic-lockfile|js-digest|src/hooks/deps|/dev/(tcp|udp)/'
HIGH+="|(^|[^[:alnum:]_])${EV}[[:space:](]"
HIGH+='|base64[[:space:]]+(--?decode|--?d\b|-[a-z]*d\b)'
HIGH+='|(^|[^[:alnum:]_])(source|\.)[[:space:]]+<\('
HIGH+='|\|[[:space:]]*(/[^|[:space:]]*/)?(ba|z|da|k|tc|a|c)?sh\b'
HIGH+='|\|[[:space:]]*(/[^|[:space:]]*/)?(python[0-9.]*|perl|ruby|node|deno|php)\b'

# --- REVIEW: legitimate-but-look-at-it --------------------------------------
REVIEW='\b(npm|npx|pnpm|yarn|bun|bunx|node|deno|ts-node|python[0-9.]*|ruby|perl|php)\b'
REVIEW+='|\bgo[[:space:]]+run\b|\bcargo[[:space:]]+(install|run)\b'                 # interpreters/toolchains
REVIEW+='|\b(curl|wget|aria2c|nc|ncat|scp|sftp|fetch|gio)\b'                        # fetchers
REVIEW+='|\b(ba|z|da|k|tc)?sh[[:space:]]+['"'"'"$]'                                 # shell executes a quoted/var path (e.g. sh "$srcdir/x")
REVIEW+='|git[[:space:]]+clone|git\+(https?|git|ssh|rsync)://'
REVIEW+='|printf[[:space:]]+[^;]*\\x[0-9a-f]|\brev\b|\$\{[A-Za-z_][A-Za-z0-9_]*//'  # obfuscation primitives
REVIEW+='|(sha[0-9]+sums|b2sums|md5sums)[^=]*=.*SKIP'                               # checksum bypass
# install scriptlets — flagged for intent (their bodies are also grepped above)
HOOKS='^[[:space:]]*(pre|post)_(install|upgrade|remove)[[:space:]]*\(\)'

collect() {
  local t=$1
  if [[ -f "$t" ]]; then printf '%s\n' "$t"; return; fi
  # -L follows symlinked dirs; depth raised; PKGBUILD/.install/.SRCINFO only
  find -L "$t" -maxdepth 5 \( -name PKGBUILD -o -name '*.install' -o -name '.SRCINFO' \) 2>/dev/null
}

# collect + de-duplicate target files
declare -A seen=()
files=()
for arg in "$@"; do
  while IFS= read -r f; do
    [[ -n "$f" && -z "${seen[$f]:-}" ]] && { seen[$f]=1; files+=("$f"); }
  done < <(collect "$arg")
done

if [[ ${#files[@]} -eq 0 ]]; then
  echo "No PKGBUILD/.install/.SRCINFO found under: $*" >&2
  echo "(exit 64 = could not scan — treat as UNKNOWN, not safe)" >&2
  exit 64
fi

rc=0
for f in "${files[@]}"; do
  # NUL byte => grep would treat the file as binary and silently match nothing.
  # Scan with -a regardless, and flag the NUL itself as suspicious.
  nul=0; [[ $(LC_ALL=C tr -cd '\000' < "$f" | wc -c) -gt 0 ]] && nul=1
  h=$(LC_ALL=C grep -naEi "$HIGH"   "$f" 2>/dev/null || true)
  r=$(LC_ALL=C grep -naEi "$REVIEW" "$f" 2>/dev/null || true)
  k=$(LC_ALL=C grep -naE  "$HOOKS"  "$f" 2>/dev/null || true)
  [[ $nul -eq 0 && -z "$h$r$k" ]] && continue
  echo "### $f"
  if [[ $nul -eq 1 ]]; then echo "  [HIGH] file contains NUL byte(s) — binary obfuscation, defeats text scanners"; rc=2; fi
  if [[ -n "$h" ]]; then echo "  [HIGH] code-exec / payload-staging / IOC markers:"; sed 's/^/    /' <<<"$h"; rc=2; fi
  if [[ -n "$k" ]]; then echo "  [HOOK] install scriptlet present (review its intent):"; sed 's/^/    /' <<<"$k"; [[ $rc -lt 1 ]] && rc=1; fi
  if [[ -n "$r" ]]; then echo "  [REVIEW] runs a toolchain/fetcher/obfuscation/checksum-skip — eyeball:"; sed 's/^/    /' <<<"$r"; [[ $rc -lt 1 ]] && rc=1; fi
  echo
done

case $rc in
  0) echo "review-pkgbuild: no markers in ${#files[@]} file(s) — but this is NOT a safety guarantee; read the diff." ;;
  1) echo "review-pkgbuild: REVIEW markers — recipe runs code/fetches; a human must read the lines above." ;;
  2) echo "review-pkgbuild: HIGH-RISK markers — do NOT build until a human clears them." ;;
esac
exit $rc
