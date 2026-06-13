# aur-safe-update

A [Claude Code](https://claude.com/claude-code) **skill** (Arch Linux only) that
performs a full system update — official repos **plus** the AUR — behind a
supply-chain safety gate.

Official repositories (`[core]/[extra]/[multilib]`) are signed and trusted. The
AUR is not: any maintainer (or anyone who adopts an orphaned package) can put
arbitrary code in a `PKGBUILD` that runs at build/install time. This skill makes
that step **reviewable by a human** instead of automatic.

> Built in response to the **June 2026 `atomic-lockfile` AUR campaign**, in which
> hundreds-to-~1,500 orphaned AUR packages were reportedly hijacked to ship an
> infostealer + eBPF rootkit via a malicious `npm`/`bun` install hook.

> [!IMPORTANT]
> **The real gate is you reading the diff.** The bundled scripts are *advisory
> aids, not gates*: `review-pkgbuild.sh` is a regex over arbitrary bash and can be
> evaded by obfuscation; `scan-iocs.sh` cannot detect a rootkit that hides its own
> artifacts, and the compromised-name list lags reality. A "clean" result means
> "no obvious markers," **not** "proven safe."

## What it does

1. **Pre-flight sweep** — IOC scan (eBPF rootkit maps, suspicious systemd
   persistence, `atomic-lockfile`/`js-digest` npm/bun artifacts) and a
   **provides-aware** cross-check of installed packages against the
   known-compromised list. It *reports* indicators and sets an exit code; the
   agent stops on indicators (it does not kill your shell).
2. **Official repos** — preview via `checkupdates`, then `sudo pacman -Syu`.
3. **AUR gate** — for every pending AUR update, fetch the *incoming* `PKGBUILD`,
   scan it for markers, and diff it against the last recipe that was built (when
   a cached copy exists) so a human can see what changed.
4. **Apply** — the workflow instructs the agent to hold anything with HIGH-risk
   markers and to never use `--noconfirm`/`--nodiff` on AUR builds; it applies
   only after explicit human approval.
5. **Post-update sweep** — re-runs the IOC scan.

The **PKGBUILD diff review is the permanent, campaign-agnostic layer**; the
compromised-list cross-check is a removable "incident layer."

> [!NOTE]
> The workflow runs as `plan-update.sh` (dry run: clone + pin commit + scan + diff)
> → human approval → `apply-update.sh --confirm` (TOCTOU-guarded single
> `pikaur -Syu` transaction). Optional `--sources` also scans fetched `source=()`
> trees. Residual limits & future work are tracked in
> [issues](https://github.com/nicolasacchi/aur-safe-update/issues).

## Install

Repeat these steps on **each Arch machine** you want it on (it's a per-user
Claude Code skill, not a system package).

**1. Prerequisites**

```bash
sudo pacman -S --needed git curl pacman-contrib      # checkupdates + git + curl
```

You also need an AUR helper — this skill targets [`pikaur`](https://github.com/actionless/pikaur).
If you don't have one yet, bootstrap it once:

```bash
git clone https://aur.archlinux.org/pikaur.git && cd pikaur && makepkg -si && cd -
```

(`yay`/`paru` work too — adapt the `-Qua`/`-Syu`/`-G` calls; AUR enumeration needs
a helper, **not** bare `pacman`.)

**2. Clone the skill into your Claude Code skills directory**

```bash
git clone https://github.com/nicolasacchi/aur-safe-update.git ~/.claude/skills/aur-safe-update
chmod +x ~/.claude/skills/aur-safe-update/scripts/*.sh
```

Keep the folder name `aur-safe-update` — Claude Code discovers skills by directory
and it must match the skill's `name:`. That's it; start (or `/reload`) Claude Code
and the `/aur-safe-update` skill is available.

**3. (optional) Pre-approve a known-genuine provides-alias** so sweeps run green:

```bash
mkdir -p ~/.config/aur-safe-update && echo 'stripe-cli-bin' >> ~/.config/aur-safe-update/allow.txt
```

**Update the skill later (any machine):**

```bash
git -C ~/.claude/skills/aur-safe-update pull
```

## Usage (inside Claude Code)

Ask Claude to *“update my system”* (or run `/aur-safe-update`). It walks the flow
and **pauses for your approval before anything is built or installed**:

1. **Sweep** — host IOC check (run with `sudo` to include the eBPF check).
2. **Plan** *(dry run)* — clones, **pins the commit**, and scans every pending AUR
   update; prints **GO / REVIEW / HOLD**. `--sources` also scans fetched
   `source=()` trees; `--devel` includes `-git`/`-svn` packages.
3. **Approval gate** — it stops and shows you what will upgrade and what's held. It
   never builds on its own.
4. **Apply** — on your OK, run interactively:
   `bash ~/.claude/skills/aur-safe-update/scripts/apply-update.sh --confirm`
   — it re-verifies each pinned commit (TOCTOU guard) and runs **one**
   `pikaur -Syu` (official repos + AUR together, held packages excluded), keeping
   pikaur's own diff prompt as the final per-package check.
5. **Re-sweep** to confirm a clean result.

## Using the scripts standalone

All scripts run without Claude — handy in CI or a cron healthcheck. Run from the
clone dir (or use absolute paths):

```bash
cd ~/.claude/skills/aur-safe-update

# full flow
scripts/plan-update.sh --devel --sources        # dry run: clone+pin+scan all pending AUR updates
scripts/apply-update.sh --confirm               # TOCTOU-guarded single `pikaur -Syu` (interactive)

# IOC sweep + provides-aware compromised-list cross-check
scripts/scan-iocs.sh --fetch                    # fetch the live community list
sudo scripts/scan-iocs.sh --fetch               # sudo => also runs the eBPF check

# scan one recipe / one source tree directly
scripts/review-pkgbuild.sh ~/.cache/pikaur/build/somepkg
scripts/review-sources.sh  ~/.cache/pikaur/build/somepkg   # fetches+scans its source=()
```

**Exit codes**
- `scan-iocs.sh`: `0` clean · `1` needs attention / a check was skipped (e.g. eBPF
  without sudo) · `2` indicators found.
- `review-pkgbuild.sh` / `review-sources.sh`: `0` no markers · `1` REVIEW · `2` HIGH-risk ·
  `64` could not scan (treat as UNKNOWN, not safe).
- `plan-update.sh`: writes the plan, always `0`. `apply-update.sh`: `10` no `--confirm`
  (dry run) · `11` a recipe changed since review (TOCTOU abort) · else pikaur's status.

> Without `sudo`, the eBPF check is reported `SKIPPED` (not a failure), so a
> healthy host returns `0`. The eBPF rootkit check only looks for three known map
> names — a clean result does not prove absence of a rootkit.

**Environment knobs**

| Var | Default | Purpose |
|-----|---------|---------|
| `WINDOW_START` | `2026-06-09` | start of the incident date window |
| `WINDOW_END` | **today** | end of the window (tracks the run date) |
| `AUR_LIST_URL` | lenucksi raw list | override the compromised-name list source |
| `AUR_SAFE_ALLOW` | *(empty)* | space-separated names to silence (also reads `~/.config/aur-safe-update/allow.txt`) |
| `AUR_SAFE_SRC_MAXBYTES` | `26214400` | per-source download cap for `--sources` (bigger sources skipped) |
| `AUR_SAFE_STATE` | `~/.cache/aur-safe-update` | plan file + approved-snapshot location |

### Why "provides-aware" matters

`pacman -Qmq <name>` resolves `provides`, so a `-bin` package can match a listed
*source* package name (e.g. `stripe-cli-bin` provides `stripe-cli`). The scanner
reports that as **`[VERIFY]`** — it may be a benign alias *or* a hijacked variant,
so it is treated as an indicator until you confirm the binary, then allowlist it.
This avoids both a false "clean" (a real hijacked alias hidden) and permanent noise.

## Incident references

- Authoritative live list: <https://md.archlinux.org/s/SxbqukK6IA>
- Community detection repo: <https://github.com/lenucksi/aur-malware-check>

## Disclaimer

A safety aid, **not a guarantee**. It reduces the risk of building a poisoned AUR
package; it cannot prove a package — or a host — is clean. The scanners are
heuristic and evadable, and a rootkit hides itself. Always read the diffs.
Provided "as is", no warranty — see [LICENSE](LICENSE).
