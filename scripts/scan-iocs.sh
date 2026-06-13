#!/usr/bin/env bash
#
# scan-iocs.sh — post/pre-update safety sweep for AUR supply-chain malware.
#
# Two layers:
#   (A) IOC sweep  — campaign-agnostic host hygiene: eBPF rootkit maps,
#                    suspicious systemd persistence, and the atomic-lockfile/
#                    js-digest npm|bun artifacts left by the June 2026 campaign.
#   (B) List cross-check (optional, --list/--fetch) — compares installed
#                    foreign packages against a known-compromised name list,
#                    and is PROVIDES-AWARE: a hit whose installed name differs
#                    from the list entry (e.g. stripe-cli-bin providing
#                    stripe-cli) is labelled PROVIDE-ALIAS = likely false
#                    positive, verify the actual package separately.
#
# Usage:
#   scan-iocs.sh                 # IOC sweep only
#   scan-iocs.sh --fetch         # IOC sweep + cross-check vs live community list
#   scan-iocs.sh --list FILE     # IOC sweep + cross-check vs a local list
#
# Env: WINDOW_START / WINDOW_END  (incident date window, default June 2026)
#      AUR_LIST_URL               (override the community list source)
#
# Exit codes: 0 clean | 1 needs-attention/partial | 2 indicators found
set -uo pipefail

WINDOW_START="${WINDOW_START:-2026-06-09}"
WINDOW_END="${WINDOW_END:-2026-06-13}"
AUR_LIST_URL="${AUR_LIST_URL:-https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt}"
IOC_PKGS=(atomic-lockfile js-digest)

LIST_FILE=""; DO_LIST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fetch)  DO_LIST=1 ;;
    --list)   DO_LIST=1; LIST_FILE="${2:?--list needs a path}"; shift ;;
    --list=*) DO_LIST=1; LIST_FILE="${1#*=}" ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac; shift
done

RC=0; bump(){ [[ $1 -gt $RC ]] && RC=$1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

in_window(){ local d; d=$(LC_ALL=C date -d "$1" +%F 2>/dev/null) || return 1; [[ "$d" > "$WINDOW_START" || "$d" == "$WINDOW_START" ]] && [[ "$d" < "$WINDOW_END" || "$d" == "$WINDOW_END" ]]; }

echo "============================================================"
echo " AUR safety sweep   window: $WINDOW_START .. $WINDOW_END"
echo "============================================================"

# ---- (B) compromised-list cross-check -------------------------------------
if [[ $DO_LIST -eq 1 ]]; then
  echo; echo "--- compromised-list cross-check (provides-aware) ---"
  if [[ -z "$LIST_FILE" ]]; then
    LIST_FILE="$TMP/list.txt"
    if ! curl -fsS -o "$LIST_FILE" "$AUR_LIST_URL"; then
      echo "  WARN: could not fetch list from $AUR_LIST_URL — skipping cross-check."
      bump 1; LIST_FILE=""
    fi
  fi
  if [[ -n "$LIST_FILE" && -s "$LIST_FILE" ]]; then
    mapfile -t LIST < <(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$LIST_FILE" | tr -d '\r' | sort -u)
    declare -A LSET; for n in "${LIST[@]}"; do LSET["$n"]=1; done
    echo "  checking ${#LIST[@]} names against installed foreign packages..."
    direct=0; alias=0
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      idate=$(LC_ALL=C pacman -Qi -- "$hit" 2>/dev/null | awk -F': ' '/^Install Date/{print $2; exit}')
      win="pre-incident"; in_window "$idate" && win="*** IN WINDOW ***"
      if [[ -n "${LSET[$hit]:-}" ]]; then
        echo "  [DIRECT]        $hit   (installed: $idate) $win"; direct=1; bump 2
      else
        prov=$(pacman -Qi -- "$hit" 2>/dev/null | awk -F': ' '/^Provides/{print $2}')
        echo "  [PROVIDE-ALIAS] $hit provides a listed name [$prov] — LIKELY FALSE POSITIVE, verify the binary (installed: $idate) $win"
        alias=1; bump 1
      fi
    done < <(pacman -Qmq "${LIST[@]}" 2>/dev/null | sort -u)
    [[ $direct -eq 0 && $alias -eq 0 ]] && echo "  Clean: no installed package matches the list (by name or provides)."
    echo "  NOTE: list is community-sourced and may lag. Authoritative: https://md.archlinux.org/s/SxbqukK6IA"
  fi
fi

# ---- (A) IOC sweep --------------------------------------------------------
echo; echo "--- eBPF rootkit maps (/sys/fs/bpf/hidden_*) ---"
if [[ -r /sys/fs/bpf ]]; then
  found=$(ls /sys/fs/bpf/hidden_pids /sys/fs/bpf/hidden_names /sys/fs/bpf/hidden_inodes 2>/dev/null || true)
  if [[ -n "$found" ]]; then echo "  WARNING: eBPF rootkit maps present:"; sed 's/^/    /' <<<"$found"; bump 2
  else echo "  Clean: no hidden_* maps."; fi
else
  echo "  /sys/fs/bpf not readable — re-run with sudo to fully rule out a root-level eBPF rootkit."; bump 1
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
else echo "  Clean: no matching services."; fi

echo; echo "--- npm/bun caches + node_modules for ${IOC_PKGS[*]} ---"
cache_hit=0
for pkg in "${IOC_PKGS[@]}"; do
  npm cache ls 2>/dev/null | grep -q "$pkg" && { echo "  WARNING: $pkg in npm cache"; cache_hit=1; }
  ncd=$(npm config get cache 2>/dev/null); [[ -d "$ncd" ]] && find "$ncd" -name "*${pkg}*" 2>/dev/null | grep -q . && { echo "  WARNING: $pkg in $ncd"; cache_hit=1; }
  bcd=$(bun pm cache 2>/dev/null || echo "$HOME/.bun/install/cache"); [[ -d "$bcd" ]] && find "$bcd" -name "*${pkg}*" 2>/dev/null | grep -q . && { echo "  WARNING: $pkg in bun cache"; cache_hit=1; }
done
[[ $cache_hit -eq 1 ]] && bump 2 || echo "  Clean: no malicious packages cached."

echo; echo "--- dropped payload artifacts (atomic-lockfile / deps) ---"
art=$(find "$HOME/.npm" "$HOME/.cache" "$HOME/.local" 2>/dev/null \( -name 'atomic-lockfile*' -o -name 'js-digest*' -o -path '*src/hooks/deps' \) | head -20)
if [[ -n "$art" ]]; then echo "  WARNING: artifacts found:"; sed 's/^/    /' <<<"$art"; bump 2
else echo "  Clean: no dropped artifacts."; fi

echo; echo "============================================================"
case $RC in
  0) echo " RESULT: CLEAN" ;;
  1) echo " RESULT: NEEDS ATTENTION — review notes above (or re-run with sudo)" ;;
  2) echo " RESULT: INDICATORS FOUND — treat as compromised, follow incident response" ;;
esac
echo "============================================================"
exit $RC
