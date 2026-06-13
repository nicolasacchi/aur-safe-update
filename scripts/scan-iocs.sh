#!/usr/bin/env bash
#
# scan-iocs.sh — pre/post-update safety sweep for AUR supply-chain malware.
#
# ADVISORY, not a guarantee: a rootkit hides its own artifacts, and the
# compromised-name list lags reality. A CLEAN result does not prove a clean
# host — it means none of these specific indicators were visible.
#
# Two layers:
#   (A) IOC sweep  — eBPF rootkit maps, suspicious systemd persistence, and the
#                    atomic-lockfile/js-digest npm|bun artifacts.
#   (B) List cross-check (--list/--fetch) — installed foreign packages vs a
#                    known-compromised name list. PROVIDES-AWARE: a hit whose
#                    installed name differs from the list entry (e.g.
#                    stripe-cli-bin providing stripe-cli) is reported as
#                    [VERIFY] — it may be a benign alias OR a hijacked variant,
#                    so it is treated as an indicator until a human clears it.
#                    Use an allowlist to silence confirmed-benign aliases.
#
# Usage:
#   scan-iocs.sh                 # IOC sweep only
#   scan-iocs.sh --fetch         # + cross-check vs live community list
#   scan-iocs.sh --list FILE     # + cross-check vs a local list
#
# Env: WINDOW_START (default 2026-06-09) / WINDOW_END (default = today)
#      AUR_LIST_URL  — override the community list source
#      AUR_SAFE_ALLOW="pkg1 pkg2"  — allowlist (also ~/.config/aur-safe-update/allow.txt)
#
# Exit codes: 0 clean | 1 needs-attention/partial/skipped | 2 indicators found
set -uo pipefail

WINDOW_START="${WINDOW_START:-2026-06-09}"
WINDOW_END="${WINDOW_END:-$(date +%F)}"          # track run date, not a frozen day
AUR_LIST_URL="${AUR_LIST_URL:-https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt}"
IOC_PKGS=(atomic-lockfile js-digest)

LIST_FILE=""; DO_LIST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fetch)  DO_LIST=1 ;;
    --list)   DO_LIST=1; LIST_FILE="${2:?--list needs a path}"; shift ;;
    --list=*) DO_LIST=1; LIST_FILE="${1#*=}" ;;
    -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac; shift
done

RC=0; bump(){ [[ $1 -gt $RC ]] && RC=$1; }
SKIPPED=()
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# allowlist of confirmed-benign package names (env + optional file)
declare -A ALLOW=()
for n in ${AUR_SAFE_ALLOW:-}; do ALLOW["$n"]=1; done
AF="$HOME/.config/aur-safe-update/allow.txt"
[[ -r "$AF" ]] && while IFS= read -r n; do n="${n%%#*}"; n="${n//[[:space:]]/}"; [[ -n "$n" ]] && ALLOW["$n"]=1; done < "$AF"

# in-window only for a strict YYYY-MM-DD that parses; empty/garbage => false
in_window(){
  local raw=$1 d
  [[ -z "$raw" ]] && return 1
  d=$(LC_ALL=C date -d "$raw" +%F 2>/dev/null) || return 1
  [[ "$d" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
  [[ "$d" > "$WINDOW_START" || "$d" == "$WINDOW_START" ]] && [[ "$d" < "$WINDOW_END" || "$d" == "$WINDOW_END" ]]
}

echo "============================================================"
echo " AUR safety sweep   window: $WINDOW_START .. $WINDOW_END"
echo " (advisory — a CLEAN result is not proof of a clean host)"
echo "============================================================"

# ---- (B) compromised-list cross-check -------------------------------------
if [[ $DO_LIST -eq 1 ]]; then
  echo; echo "--- compromised-list cross-check (provides-aware) ---"
  if [[ -z "$LIST_FILE" ]]; then
    LIST_FILE="$TMP/list.txt"
    if ! curl -fsS -o "$LIST_FILE" "$AUR_LIST_URL"; then
      echo "  WARN: could not fetch list from $AUR_LIST_URL — skipping cross-check."
      SKIPPED+=("compromised-list (fetch failed)"); bump 1; LIST_FILE=""
    fi
  fi
  if [[ -n "$LIST_FILE" && -s "$LIST_FILE" ]]; then
    mapfile -t LIST < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$LIST_FILE" | tr -d '\r' | sort -u)
    if [[ ${#LIST[@]} -eq 0 ]]; then
      echo "  WARN: list is empty after stripping comments/blanks (truncated download?) — skipping."
      SKIPPED+=("compromised-list (empty)"); bump 1
    else
      declare -A LSET=(); for n in "${LIST[@]}"; do LSET["$n"]=1; done
      echo "  checking ${#LIST[@]} names against installed foreign packages..."
      hits=0
      while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        idate=$(LC_ALL=C pacman -Qi -- "$hit" 2>/dev/null | awk -F': ' '/^Install Date/{print $2; exit}')
        win="pre-incident"; in_window "$idate" && win="*** IN WINDOW ***"
        kind="DIRECT"; [[ -z "${LSET[$hit]:-}" ]] && kind="PROVIDES"
        if [[ -n "${ALLOW[$hit]:-}" ]]; then
          echo "  [ALLOWLISTED] $hit ($kind match) — silenced by allowlist (installed: $idate)"
          hits=1; continue
        fi
        if [[ "$kind" == "DIRECT" ]]; then
          echo "  [DIRECT]  $hit  — name is on the compromised list (installed: $idate) $win"
        else
          prov=$(pacman -Qi -- "$hit" 2>/dev/null | awk -F': ' '/^Provides/{print $2}')
          echo "  [VERIFY]  $hit  provides a listed name [$prov] — benign alias (e.g. a -bin variant) OR hijacked; verify the binary (installed: $idate) $win"
        fi
        hits=1; bump 2
      done < <(pacman -Qmq "${LIST[@]}" 2>/dev/null | sort -u)
      [[ $hits -eq 0 ]] && echo "  Clean: no installed package matches the list (by name or provides)."
      echo "  NOTE: list is community-sourced and may lag. Authoritative: https://md.archlinux.org/s/SxbqukK6IA"
    fi
  fi
fi

# ---- (A) IOC sweep --------------------------------------------------------
echo; echo "--- eBPF rootkit maps (/sys/fs/bpf/hidden_*) ---"
if [[ -r /sys/fs/bpf ]]; then
  found=$(ls /sys/fs/bpf/hidden_pids /sys/fs/bpf/hidden_names /sys/fs/bpf/hidden_inodes 2>/dev/null || true)
  if [[ -n "$found" ]]; then echo "  WARNING: eBPF rootkit maps present:"; sed 's/^/    /' <<<"$found"; bump 2
  else echo "  Clean: no known hidden_* maps (only checks 3 known names)."; fi
else
  echo "  SKIPPED: /sys/fs/bpf not readable — re-run with sudo for the eBPF check."
  SKIPPED+=("eBPF maps (needs sudo)")
fi

echo; echo "--- systemd persistence (Restart=always + RestartSec=30) ---"
shits=""
for d in /etc/systemd/system "$HOME/.config/systemd/user"; do
  [[ -d "$d" ]] || continue
  while IFS= read -r svc; do
    grep -q 'Restart=always' "$svc" 2>/dev/null && grep -q 'RestartSec=30' "$svc" 2>/dev/null && shits+="    $svc"$'\n'
  done < <(find "$d" -name '*.service' -type f 2>/dev/null)
done
if [[ -n "$shits" ]]; then echo "  WARNING: services matching the malware persistence profile:"; printf '%s' "$shits"; bump 2
else echo "  Clean: no matching services (narrow heuristic — see Tier-2 TODO)."; fi

echo; echo "--- npm/bun caches + node_modules for ${IOC_PKGS[*]} ---"
cache_hit=0
for pkg in "${IOC_PKGS[@]}"; do
  npm cache ls 2>/dev/null | grep -qE "(^|[/@:[:space:]])${pkg}([@/[:space:]]|$)" && { echo "  WARNING: $pkg in npm cache"; cache_hit=1; }
  ncd=$(npm config get cache 2>/dev/null); [[ -d "$ncd" ]] && find "$ncd" \( -name "$pkg" -o -name "${pkg}-*.tgz" \) 2>/dev/null | grep -q . && { echo "  WARNING: $pkg in $ncd"; cache_hit=1; }
  bcd=$(bun pm cache 2>/dev/null || echo "$HOME/.bun/install/cache"); [[ -d "$bcd" ]] && find "$bcd" \( -name "$pkg" -o -name "${pkg}@*" \) 2>/dev/null | grep -q . && { echo "  WARNING: $pkg in bun cache"; cache_hit=1; }
done
[[ $cache_hit -eq 1 ]] && bump 2 || echo "  Clean: no malicious packages cached."

echo; echo "--- dropped payload artifacts (atomic-lockfile / deps) ---"
art=$(find "$HOME/.npm" "$HOME/.cache" "$HOME/.local" \( -name 'atomic-lockfile' -o -name 'atomic-lockfile-*.tgz' -o -name 'js-digest' -o -name 'js-digest-*.tgz' -o -path '*src/hooks/deps' \) 2>/dev/null | head -20)
if [[ -n "$art" ]]; then echo "  WARNING: artifacts found:"; sed 's/^/    /' <<<"$art"; bump 2
else echo "  Clean: no dropped artifacts."; fi

echo; echo "============================================================"
case $RC in
  0) echo " RESULT: CLEAN (advisory — not proof; a rootkit hides itself)" ;;
  1) echo " RESULT: NEEDS ATTENTION — review notes above (or re-run with sudo)" ;;
  2) echo " RESULT: INDICATORS FOUND — verify each, treat as compromised if confirmed" ;;
esac
[[ ${#SKIPPED[@]} -gt 0 ]] && printf ' SKIPPED checks: %s\n' "$(IFS=', '; echo "${SKIPPED[*]}")"
echo "============================================================"
exit "$RC"
