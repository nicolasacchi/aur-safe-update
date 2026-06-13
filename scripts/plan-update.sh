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
# Usage: plan-update.sh [--devel] [--sources]
#   --devel    also plan -git/-svn dev packages (they build from upstream HEAD)
#   --sources  also fetch & scan each source=() tree (review-sources.sh) — slower
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

DEVEL=""; SOURCES=0
for a in "$@"; do case "$a" in
  --devel)   DEVEL="--devel" ;;
  --sources) SOURCES=1 ;;
  -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
esac; done
SRCREVIEW="$HERE/review-sources.sh"

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

  # optional source-tree scan (#3): fetch + scan source=() for lifecycle hooks/IOCs
  ssec=0; sout=""
  if [[ $SOURCES -eq 1 ]]; then sout="$(bash "$SRCREVIEW" "$dir" 2>&1)"; ssec=$?; fi
  # devel detection (#4): -git/-svn/... or a pkgver() => builds from upstream HEAD
  devel=0
  case "$P" in *-git|*-svn|*-hg|*-bzr|*-cvs|*-darcs|*-nightly) devel=1 ;; esac
  grep -qE '^[[:space:]]*pkgver[[:space:]]*\(\)' "$pb" 2>/dev/null && devel=1
  worst=$(( sec > ssec ? sec : ssec ))

  if [[ $worst -eq 2 || $worst -eq 64 ]]; then
    tag="HOLD";   detail="scan exit $sec, sources $ssec"; nhold=$((nhold+1))
  elif [[ $worst -eq 1 || "$changed" != "unchanged" || $devel -eq 1 ]]; then
    tag="REVIEW"; detail="$changed (scan $sec, sources $ssec)"; nreview=$((nreview+1))
  else
    tag="GO";     detail="unchanged since approved, no markers"; ngo=$((ngo+1))
  fi
  [[ $devel -eq 1 ]] && detail="$detail [DEVEL: builds upstream HEAD — pin covers recipe only]"

  printf '%s\t%s\t%s\t%s\t%s\n' "$P" "$base" "$commit" "$tag" "$detail" >> "$PLAN"
  printf '  [%-6s] %s  base=%s @%s  (%s%s)\n' "$tag" "$P" "$base" "${commit:0:10}" "$changed" "$([[ $devel -eq 1 ]] && echo ', devel')"
  [[ $sec  -ne 0 ]] && grep -E '\[(HIGH|REVIEW|HOOK)\]' <<<"$scan" | sed 's/^/        /'
  [[ $ssec -ne 0 ]] && grep -E '\[(HIGH|REVIEW)\]' <<<"$sout" | sed 's/^/        src: /'
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
