---
name: aur-safe-update
description: Run a full system update (official pacman repos + AUR via pikaur) with a supply-chain safety gate. Use when the user asks to update their system, run updates, upgrade packages, "pacman -Syu", "update AUR", "pikaur -Syu", or do a safe/secure update. Reviews every AUR PKGBUILD diff for malware markers, cross-checks pending updates against the known-compromised AUR list, requires explicit human approval, and runs an IOC sweep before and after.
---

# Safe Update (Arch: official repos + AUR gate)

Update the whole system so you **don't silently build a poisoned AUR package**.
Official repos (`[core]/[extra]/[multilib]`) are signed and trusted; the AUR is
not — so the gate lives on the AUR step.

**What the gate really is:** a *human reading the PKGBUILD diff* (Step 3). The
bundled scripts are **advisory aids, not gates** — `review-pkgbuild.sh` is a
regex over arbitrary bash and can be evaded by obfuscation; `scan-iocs.sh`
cannot see a rootkit that hides itself. Treat a "clean" script result as "no
obvious red flags," never as proof. The human approval (Step 2) plus pikaur's own
diff prompt at apply time (Step 3) are the real control.

This skill targets **pikaur** (the user's helper). For `yay`/`paru`, adapt the
commands — AUR enumeration needs a helper (`pikaur -Qua` / `yay -Qua`), **not**
bare `pacman` (`pacman -Qua` is invalid).

## Prerequisites
- `pikaur` (AUR helper), `pacman-contrib` (for `checkupdates`), `curl`
- Bundled scripts (next to this file; make executable once):
  - `scripts/scan-iocs.sh` — IOC sweep + provides-aware compromised-list cross-check
  - `scripts/review-pkgbuild.sh` — PKGBUILD/.install marker scanner (advisory)
  - `scripts/plan-update.sh` — clones + pins + scans pending AUR updates (dry run)
  - `scripts/apply-update.sh` — TOCTOU-guarded single-transaction apply (hard stop)
- `git`, `sudo` (apply runs `pikaur -Syu` interactively)

## Hard rules
1. **Never** pass `--noconfirm` to an AUR build, and never auto-accept a PKGBUILD
   diff. **Wait for a human message that explicitly approves** before any `sudo`
   or `pikaur -S*` command. Do not infer approval from your own analysis.
2. If Step 0 or any later sweep returns **INDICATORS FOUND**, STOP and report —
   do not update on top of a possibly-compromised host.
3. Held packages (review `[HIGH]`/NUL/scan-failed, or a **DIRECT** compromised-list
   hit) are auto-excluded by `apply-update.sh` via `--ignore` in a single
   `pikaur -Syu` transaction. Never bypass that with a bare `pikaur -Sua`, and
   never pass `--nodiff`.
4. A **[VERIFY]** (provides-match) hit is treated as an indicator until a human
   clears it — it may be a benign alias (e.g. `stripe-cli-bin` provides
   `stripe-cli`) **or** a hijacked variant. Verify the actual binary; once
   confirmed benign, silence it via the allowlist (`AUR_SAFE_ALLOW="name"` or
   `~/.config/aur-safe-update/allow.txt`), don't just ignore it.

## Workflow

### Step 0 — pre-flight sweep
```bash
bash ~/.claude/skills/aur-safe-update/scripts/scan-iocs.sh --fetch
```
Read the result. `CLEAN` → proceed. `NEEDS ATTENTION` → check the `SKIPPED`
line: a lone "eBPF maps (needs sudo)" is benign; anything else, look closer.
`INDICATORS FOUND` → stop, verify each hit, switch to incident response (rotate
creds, investigate) if confirmed. Capture the printed DIRECT/VERIFY names for Step 2.

### Step 1 — plan (dry run; no changes, no sudo)
Preview official updates, then run the AUR planner:
```bash
checkupdates 2>/dev/null            # official repo preview (signed/trusted)
bash ~/.claude/skills/aur-safe-update/scripts/plan-update.sh           # add --devel for -git/-svn pkgs
```
`plan-update.sh` clones each pending AUR package, **pins the exact commit**, scans
it with `review-pkgbuild.sh`, and diffs it against the last *approved* snapshot. It
writes `~/.cache/aur-safe-update/plan.tsv` and prints a per-package verdict:
- **GO** — unchanged since last approval, no markers.
- **REVIEW** — recipe changed, or a `[REVIEW]`/`[HOOK]` marker — a human reads the shown lines/diff.
- **HOLD** — `[HIGH]`/NUL/scan-failed (exit 64) — auto-excluded from the upgrade.
Relay the GO/REVIEW/HOLD list and the diffs/markers shown. (If `checkupdates` is
missing: `sudo pacman -S pacman-contrib`.)

### Step 2 — human approval (hard stop)
**Stop and wait for an explicit human approval message** before applying — do not
infer approval from your own analysis. Summarize what will upgrade, what is held,
and the REVIEW items the human should eyeball. For any **DIRECT**/**[VERIFY]**
compromised-list hit from Step 0, confirm the package before approving.

### Step 3 — apply (single transaction; human-run, interactive)
On approval, run **interactively** (needs the sudo password and shows pikaur's own
diff prompts — never headless or `--nodiff`):
```bash
bash ~/.claude/skills/aur-safe-update/scripts/apply-update.sh --confirm
```
It re-verifies every pinned commit is **unchanged since review** (aborts if a recipe
moved — the TOCTOU guard), then runs **one** `pikaur -Syu --needed` with held
packages `--ignore`d — official repos and AUR upgrade together, so no partial-upgrade
state. pikaur's diff prompt is the final per-package check; compare it to what Step 1
showed. On success it refreshes the approved snapshots. Without `--confirm` it is a
dry run (prints the exact command + held list, changes nothing).

### Step 4 — post-update sweep
```bash
bash ~/.claude/skills/aur-safe-update/scripts/scan-iocs.sh --fetch
```
Report: official packages updated, AUR packages updated, any held, and the verdict.

## Notes
- **Current incident (June 2026 `atomic-lockfile`):** the cross-check uses the
  community list at `lenucksi/aur-malware-check`; authoritative live list is
  <https://md.archlinux.org/s/SxbqukK6IA>. Once Arch declares the AUR clean, drop
  `--fetch` and rely on the PKGBUILD review + IOC sweep (the permanent layers).
- **Env knobs** (`scan-iocs.sh`): `WINDOW_START`/`WINDOW_END` (window defaults to
  `2026-06-09 .. today`), `AUR_LIST_URL`, `AUR_SAFE_ALLOW` (+ `~/.config/aur-safe-update/allow.txt`).
- **Provides-aware:** `pacman -Qmq <listname>` resolves `provides`, so a `-bin`
  package matches a listed source name; the scanner reports `[VERIFY]`, not a
  false "clean".
- Run `scan-iocs.sh` with **sudo** for the eBPF check (unprivileged runs report it `SKIPPED`).
- **Automated by the plan/apply scripts:** commit-pinned review == built tree
  (TOCTOU guard), single `pikaur -Syu` transaction (no partial upgrade), held
  packages `--ignore`d, persistent approved-snapshot diffs, pkgbase/split
  resolution (via `pikaur -G`), and the `--confirm` hard stop.
- **Remaining gap (issue #3):** neither script inspects fetched `source=()` trees,
  where an upstream `package.json` lifecycle hook / `setup.py` can also run at
  build time. Until that lands, eyeball the sources of any REVIEW package that
  pulls a VCS/tarball source.
