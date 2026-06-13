#!/usr/bin/env bash
#
# plan-update.sh — pre-brief for a safe AUR update. NO system changes, NO sudo.
#
# For each pending AUR package it: clones the AUR repo (pinning the exact commit
# that will be reviewed), scans the recipe with review-pkgbuild.sh, and diffs it
# against the last *approved* snapshot (a persistent baseline, unlike pikaur's
# volatile build dir). It writes a machine-readable plan that apply-update.sh
# consumes. This is the dry-run / review stage — run it freely.
#
# Usage: plan-update.sh [--devel]
#
# Plan file (TSV): name <TAB> pkgbase <TAB> commit <TAB> TAG <TAB> detail
#   TAG = GO | REVIEW | HOLD
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REVIEW="$HERE/review-pkgbuild.sh"
STATE="${AUR_SAFE_STATE:-$HOME/.cache/aur-safe-update}"
APPROVED="$STATE/approved"
PLAN="$STATE/plan.tsv"
mkdir -p "$APPROVED"

DEVEL=""; [[ "${1:-}" == "--devel" ]] && DEVEL="--devel"

mapfile -t PENDING < <(pikaur -Qua $DEVEL 2>/dev/null | awk 'NF{print $1}')
if [[ ${#PENDING[@]} -eq 0 ]]; then echo "No pending AUR updates."; : > "$PLAN"; exit 0; fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
: > "$PLAN"
echo "Planning ${#PENDING[@]} pending AUR update(s) — cloning + scanning (no changes made)..."
echo

ngo=0; nreview=0; nhold=0
for P in "${PENDING[@]}"; do
  mkdir -p "$WORK/$P"
  if ! pikaur -G "$P" -o "$WORK/$P" >/dev/null 2>&1; then
    printf '%s\t?\t?\tHOLD\tclone failed (could not fetch recipe)\n' "$P" >> "$PLAN"
    echo "  [HOLD]   $P — clone failed"; nhold=$((nhold+1)); continue
  fi
  pb="$(find "$WORK/$P" -maxdepth 2 -name PKGBUILD -print -quit 2>/dev/null)"
  if [[ -z "$pb" ]]; then
    printf '%s\t?\t?\tHOLD\tno PKGBUILD in clone\n' "$P" >> "$PLAN"
    echo "  [HOLD]   $P — no PKGBUILD found"; nhold=$((nhold+1)); continue
  fi
  dir="$(dirname "$pb")"; base="$(basename "$dir")"
  commit="$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo '?')"
  scan="$(bash "$REVIEW" "$dir" 2>&1)"; sec=$?
  snap="$APPROVED/$base.PKGBUILD"
  if [[ -f "$snap" ]]; then
    diff -q "$snap" "$pb" >/dev/null 2>&1 && changed="unchanged" || changed="CHANGED"
  else
    changed="first-review"
  fi

  if [[ $sec -eq 2 || $sec -eq 64 ]]; then
    tag="HOLD";   detail="scanner: $(tail -1 <<<"$scan")"; nhold=$((nhold+1))
  elif [[ $sec -eq 1 || "$changed" != "unchanged" ]]; then
    tag="REVIEW"; detail="$changed (scanner exit $sec)"; nreview=$((nreview+1))
  else
    tag="GO";     detail="unchanged since approved, no markers"; ngo=$((ngo+1))
  fi

  printf '%s\t%s\t%s\t%s\t%s\n' "$P" "$base" "$commit" "$tag" "$detail" >> "$PLAN"
  printf '  [%-6s] %s  base=%s @%s  (%s)\n' "$tag" "$P" "$base" "${commit:0:10}" "$changed"
  [[ $sec -ne 0 ]] && grep -E '\[(HIGH|REVIEW|HOOK)\]' <<<"$scan" | sed 's/^/        /'
  if [[ "$changed" == "CHANGED" ]]; then
    echo "        recipe changed since last approval — diff (truncated to 30 lines):"
    diff -u "$snap" "$pb" 2>/dev/null | sed -n '1,30p' | sed 's/^/        /'
  fi
done

ign=""; while IFS=$'\t' read -r n _ _ t _; do [[ "$t" == "HOLD" ]] && ign+=" --ignore $n"; done < "$PLAN"
echo
echo "============================================================"
echo " Plan: $ngo GO · $nreview REVIEW · $nhold HOLD   (written to $PLAN)"
echo "============================================================"
[[ -n "$ign" ]] && echo " Held (auto-excluded from the upgrade):$ign"
echo " Next: read the REVIEW/HOLD items above. After a human approves, run INTERACTIVELY:"
echo "     bash $HERE/apply-update.sh --confirm"
echo " apply re-verifies each pinned commit, then runs ONE 'pikaur -Syu' transaction"
echo " (repos + AUR together, held excluded, pikaur's diff prompt kept as the final check)."
