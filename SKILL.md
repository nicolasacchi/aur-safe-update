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
obvious red flags," never as proof. The human approval in Steps 1 and 4 is the
real control.

This skill targets **pikaur** (the user's helper). For `yay`/`paru`, adapt the
commands — AUR enumeration needs a helper (`pikaur -Qua` / `yay -Qua`), **not**
bare `pacman` (`pacman -Qua` is invalid).

## Prerequisites
- `pikaur` (AUR helper), `pacman-contrib` (for `checkupdates`), `curl`
- Bundled scripts (next to this file; make executable once):
  - `scripts/scan-iocs.sh` — IOC sweep + provides-aware compromised-list cross-check
  - `scripts/review-pkgbuild.sh` — PKGBUILD/.install marker scanner (advisory)
- `sudo` for the official-repo step

## Hard rules
1. **Never** pass `--noconfirm` to an AUR build, and never auto-accept a PKGBUILD
   diff. **Wait for a human message that explicitly approves** before any `sudo`
   or `pikaur -S*` command. Do not infer approval from your own analysis.
2. If Step 0 or any later sweep returns **INDICATORS FOUND**, STOP and report —
   do not update on top of a possibly-compromised host.
3. Hold (skip) any AUR package whose review is `[HIGH]`/NUL, or whose name is a
   **DIRECT** compromised-list hit. **When anything is held, never run bare
   `pikaur -Sua`** (it upgrades *all* AUR packages and cannot exclude) — use
   `pikaur -S <vetted...>` or `pikaur -Sua --ignore <held1> --ignore <held2>`.
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

### Step 1 — show the official-repo plan, then apply
```bash
checkupdates 2>/dev/null            # preview official updates without touching anything
```
Show the list to the user. **Wait for explicit approval, then:**
```bash
sudo pacman -Syu                    # signed packages — trusted
```
(If `checkupdates` is missing: `sudo pacman -S pacman-contrib`.)
⚠️ **Partial-upgrade caveat (Tier-2 TODO):** applying repos here and then holding
an AUR package leaves an Arch-discouraged partial-upgrade state. If you expect to
hold AUR packages that link system libs, prefer deferring this until after Step 3,
or run the whole thing as one `pikaur -Syu` transaction.

### Step 2 — enumerate pending AUR updates
```bash
pikaur -Qua                         # lists "pkg  old -> new" for AUR only
pikaur -Qua --devel                 # also include -git/-svn (build from HEAD; highest risk)
```
If empty, skip to Step 5. Otherwise cross-check the pending names against the
DIRECT/VERIFY names from Step 0 and call them out.

### Step 3 — review each AUR PKGBUILD diff  ← the human gate
For every pending package `$P`, fetch the *incoming* recipe and scan + diff it
before any build runs:
```bash
P=<pkgname>
D=$(mktemp -d)
curl -fsS "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$P"  -o "$D/PKGBUILD"
curl -fsS "https://aur.archlinux.org/cgit/aur.git/plain/.SRCINFO?h=$P"  -o "$D/.SRCINFO" 2>/dev/null || true
# advisory marker scan:
bash ~/.claude/skills/aur-safe-update/scripts/review-pkgbuild.sh "$D"
# diff against the last recipe pikaur built (often absent if keepbuilddir=no):
diff -u "$HOME/.cache/pikaur/build/$P/PKGBUILD" "$D/PKGBUILD" 2>/dev/null || echo "(no prior build cached — review the FULL recipe)"
```
Also fetch any referenced `*.install` and scan it. Summarize per package:
**clean / REVIEW / HIGH** (and what the diff changed). **`review-pkgbuild.sh`
exit 64 = "could not scan" = UNKNOWN → hold, never treat as clean.** Red flags to
hold on: `npm/bun install` of an unknown dep, `atomic-lockfile`/`js-digest`,
pipe-to-shell, `eval`/`base64 -d`, `/dev/tcp`, a new `post_install`/`prepare()`
that fetches or runs code, `sha256sums=SKIP`, or a `source=` on a new host.
⚠️ **Two known gaps (Tier-2 TODO):** (a) this reviews the cgit copy, but Step 4's
`pikaur` clones its own — a maintainer can push between review and build (TOCTOU);
the load-bearing review is pikaur's **own** diff prompt in Step 4. (b) Neither the
scan nor the diff inspects fetched `source=()` trees, where upstream build hooks
(e.g. a malicious `package.json`) also run.

### Step 4 — apply approved AUR updates
Present the verdict and **wait for explicit human approval**. Then update the
cleared packages, **reading pikaur's own diff prompts** (do not pass `--nodiff`):
```bash
pikaur -S <vetted-pkg1> <vetted-pkg2>          # preferred when ANY package is held
# only if nothing is held:  pikaur -Sua
# alternative:  pikaur -Sua --ignore <held1> --ignore <held2>
```
Tell the user which packages were held and why (and to check the Arch pad before forcing them).

### Step 5 — post-update sweep
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
- **Split packages:** if `?h=$P` 404s, `$P` is a split member — fetch the pkgbase
  (`pacman -Qi $P` → `Base`) instead, and treat any failed fetch as a hold.
