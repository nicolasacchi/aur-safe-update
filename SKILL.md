---
name: safe-update
description: Run a full system update (official pacman repos + AUR via pikaur) with a supply-chain safety gate. Use when the user asks to update their system, run updates, upgrade packages, "pacman -Syu", "update AUR", "pikaur -Syu", or do a safe/secure update. Reviews every AUR PKGBUILD diff for malware markers, cross-checks pending updates against the known-compromised AUR list, requires explicit approval, and runs an IOC sweep before and after.
---

# Safe Update (Arch: official repos + AUR gate)

Update the whole system in a way that **cannot silently build a poisoned AUR
package**. Official repos (`[core]/[extra]/[multilib]`) are signed and trusted;
the AUR is not — so the gate lives on the AUR step. The permanent defense is the
**PKGBUILD diff review** (Step 3): it does not depend on any known-bad list and
keeps working long after the June 2026 `atomic-lockfile` campaign is over.

This skill targets **pikaur** (the user's helper). Swap commands if they switch.

## Prerequisites
- `pikaur` (AUR helper), `pacman-contrib` (for `checkupdates`), `curl`
- Bundled scripts (next to this file, make executable once):
  - `scripts/scan-iocs.sh` — IOC sweep + provides-aware compromised-list cross-check
  - `scripts/review-pkgbuild.sh` — PKGBUILD/.install marker scanner (the core gate)
- `sudo` for the official-repo step

## Hard rules
1. **Never** pass `--noconfirm` to an AUR build, and never auto-accept a PKGBUILD
   diff. Every changed AUR recipe gets reviewed and explicitly approved.
2. If Step 0 or any later sweep returns **INDICATORS FOUND**, STOP and report —
   do not update on top of a possibly-compromised host.
3. Hold (skip) any AUR package whose PKGBUILD review is `[HIGH]` or whose name is
   a **DIRECT** hit on the compromised list. Let the rest proceed.
4. A **PROVIDE-ALIAS** list hit is a likely false positive (e.g. `stripe-cli-bin`
   provides `stripe-cli`). Don't block on it — verify the actual installed
   package instead (genuine upstream binary? real release version?).

## Workflow

### Step 0 — pre-flight sweep
```bash
bash ~/.claude/skills/safe-update/scripts/scan-iocs.sh --fetch
```
Read the result. `CLEAN` → proceed. `NEEDS ATTENTION` → note it (often just
"re-run with sudo for eBPF"). `INDICATORS FOUND` → stop, switch to incident
response (rotate creds, investigate), do not update.

### Step 1 — show the official-repo plan, then apply
```bash
checkupdates 2>/dev/null            # preview official updates without touching anything
```
Show the list to the user. On approval:
```bash
sudo pacman -Syu                    # signed packages — trusted; let it run
```
(If `checkupdates` is missing, tell the user to `sudo pacman -S pacman-contrib`.)

### Step 2 — enumerate pending AUR updates
```bash
pikaur -Qua                         # lists "pkg  old -> new" for AUR only
```
If empty, skip to Step 5. Otherwise cross-check the pending names against the
list surfaced in Step 0 and call out any **DIRECT** hits among them.

### Step 3 — review each AUR PKGBUILD diff  ← the gate
For every pending package `$P`, fetch the *incoming* recipe straight from the AUR
and scan + diff it before any build runs:
```bash
P=<pkgname>
D=$(mktemp -d)
curl -fsS "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$P"  -o "$D/PKGBUILD"
curl -fsS "https://aur.archlinux.org/cgit/aur.git/plain/.SRCINFO?h=$P"  -o "$D/.SRCINFO" 2>/dev/null || true
# marker scan (the campaign-agnostic defense):
bash ~/.claude/skills/safe-update/scripts/review-pkgbuild.sh "$D"
# diff against the last recipe pikaur built (what changed since you last trusted it):
diff -u "$HOME/.cache/pikaur/build/$P/PKGBUILD" "$D/PKGBUILD" 2>/dev/null || echo "(no prior build cached — review full recipe)"
```
Also fetch any referenced `*.install` file the same way and scan it. Summarize
per package: **clean / informational / HIGH**, plus what the diff changed. Red
flags to hold on: `npm|bun|npx|bunx install`, `atomic-lockfile`/`js-digest`,
`curl … | sh`, `eval`/`base64 -d`, a new `post_install`/`prepare()` that fetches
or executes anything, or a `source=` pointing at a new/unexpected host.

### Step 4 — apply approved AUR updates
Present the verdict and get explicit approval. Then update the cleared packages,
**still reviewing pikaur's own diff prompts** (do not suppress them):
```bash
pikaur -Sua                         # review/accept diffs interactively
# or only the vetted ones:  pikaur -S <pkg1> <pkg2>
```
Skip held packages and tell the user why (and to check the Arch pad before
forcing them).

### Step 5 — post-update sweep
```bash
bash ~/.claude/skills/safe-update/scripts/scan-iocs.sh --fetch
```
Confirm `CLEAN`. Report: official packages updated, AUR packages updated, any
held, and the sweep verdict.

## Notes
- **Current incident (June 2026 `atomic-lockfile`):** Step 0/5 cross-check uses
  the community list at `lenucksi/aur-malware-check`; authoritative live list is
  <https://md.archlinux.org/s/SxbqukK6IA>. Once Arch declares the AUR clean, the
  list cross-check becomes noise — you can drop the `--fetch` flag and rely on
  the PKGBUILD review + IOC sweep alone (the permanent layers).
- **Why provides-aware matters:** `pacman -Qmq <listname>` resolves `provides`,
  so a `-bin` package can match a listed source package name. The scanner labels
  that `PROVIDE-ALIAS`; verify, don't auto-remove.
- Run eBPF detection with `sudo` for a definitive result; unprivileged runs can't
  read `/sys/fs/bpf`.
