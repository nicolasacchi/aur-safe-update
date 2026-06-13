#!/usr/bin/env bash
#
# apply-update.sh — execute the plan from plan-update.sh as ONE transaction.
#
# HARD STOP: refuses to change anything without --confirm (so an agent cannot
# self-approve). Before building it RE-VERIFIES each pinned commit is unchanged
# since review (TOCTOU guard), then runs a single `pikaur -Syu` (official repos +
# AUR together — no partial-upgrade state) with held packages excluded and
# pikaur's own diff prompt kept ON as the final human checkpoint. On success it
# saves the approved recipes as the new baseline for next time.
#
# Usage:
#   apply-update.sh            # DRY RUN: print what would happen, change nothing
#   apply-update.sh --confirm  # run the real upgrade (interactive: sudo + diffs)
set -uo pipefail

STATE="${AUR_SAFE_STATE:-$HOME/.cache/aur-safe-update}"
APPROVED="$STATE/approved"
PLAN="$STATE/plan.tsv"
AUR_GIT="https://aur.archlinux.org"

CONFIRM=0; [[ "${1:-}" == "--confirm" ]] && CONFIRM=1
[[ -s "$PLAN" ]] || { echo "No plan at $PLAN — run plan-update.sh first." >&2; exit 64; }

echo "=== Plan ($PLAN) ==="
{ printf 'PACKAGE\tPKGBASE\tCOMMIT\tTAG\tDETAIL\n'; cut -c1-160 "$PLAN"; } | column -t -s$'\t' 2>/dev/null || cat "$PLAN"
echo

ignore=(); vetted=()
while IFS=$'\t' read -r name base commit tag _; do
  [[ -z "$name" ]] && continue
  if [[ "$tag" == "HOLD" ]]; then ignore+=(--ignore "$name")
  else vetted+=("$name|$base|$commit"); fi
done < "$PLAN"

if [[ $CONFIRM -ne 1 ]]; then
  echo "DRY RUN — refusing to modify the system without --confirm."
  echo "Would run:  pikaur -Syu --needed ${ignore[*]:-}"
  echo "Re-run interactively as:  bash $0 --confirm"
  exit 10
fi

# --- TOCTOU guard: pinned commit must still be HEAD on the AUR side ----------
echo "=== Verifying reviewed recipes are unchanged ==="
moved=0
for v in "${vetted[@]}"; do
  IFS='|' read -r name base commit <<<"$v"
  [[ "$commit" == "?" || -z "$commit" ]] && { echo "  skip $name (no pinned commit)"; continue; }
  now="$(git ls-remote "$AUR_GIT/$base.git" HEAD 2>/dev/null | awk '$2=="HEAD"{print $1; exit}')"
  if [[ -n "$now" && "$now" != "$commit" ]]; then
    echo "  CHANGED: $name ($base) ${commit:0:10} -> ${now:0:10}"; moved=1
  else
    echo "  ok:      $name @${commit:0:10}"
  fi
done
if [[ $moved -eq 1 ]]; then
  echo; echo "ABORT: a recipe changed since you reviewed it. Re-run plan-update.sh and review again." >&2
  exit 11
fi

# --- single transaction: repos + AUR, held excluded, diff prompt KEPT --------
echo; echo "=== pikaur -Syu --needed ${ignore[*]:-}  (review each diff prompt!) ==="
pikaur -Syu --needed "${ignore[@]}"
rc=$?

# --- on success, refresh approved snapshots (new baseline) -------------------
if [[ $rc -eq 0 && ${#vetted[@]} -gt 0 ]]; then
  mkdir -p "$APPROVED"; W="$(mktemp -d)"
  for v in "${vetted[@]}"; do
    IFS='|' read -r name base commit <<<"$v"
    mkdir -p "$W/$name"
    pikaur -G "$name" -o "$W/$name" >/dev/null 2>&1 || continue
    pb="$(find "$W/$name" -maxdepth 2 -name PKGBUILD -print -quit 2>/dev/null)"
    [[ -n "$pb" ]] && cp "$pb" "$APPROVED/$base.PKGBUILD"
  done
  rm -rf "$W"
  echo "Saved approved snapshots for next-time diffs."
fi
exit $rc
