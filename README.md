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
> This is a defensive scaffold with known limitations still being hardened
> (TOCTOU between review and build, fetched-`source=()` not scanned, partial-
> upgrade handling). See [open issues](https://github.com/nicolasacchi/aur-safe-update/issues).

## Install

```bash
git clone https://github.com/nicolasacchi/aur-safe-update.git ~/.claude/skills/aur-safe-update
chmod +x ~/.claude/skills/aur-safe-update/scripts/*.sh
```

The skill's `name:` is `aur-safe-update`, matching the directory — keep them the
same (Claude Code discovers skills by directory). Then in Claude Code, ask to
update your system, or run `/aur-safe-update`.

## Prerequisites

- [`pikaur`](https://github.com/actionless/pikaur) — the AUR helper this targets.
  It is itself an AUR package; bootstrap it once per its README, or adapt the
  commands for `yay`/`paru` (AUR enumeration needs a helper, not bare `pacman`).
- `pacman-contrib` (provides `checkupdates`) — `sudo pacman -S pacman-contrib`
- `curl`

## Using the scripts standalone

Both scripts run without Claude — handy in CI or a cron healthcheck. Run from the
clone dir (or use absolute paths):

```bash
cd ~/.claude/skills/aur-safe-update

# IOC sweep + provides-aware compromised-list cross-check
scripts/scan-iocs.sh --fetch                    # fetch the live community list
scripts/scan-iocs.sh --list ./list.txt          # or use a local list
sudo scripts/scan-iocs.sh --fetch               # sudo => also runs the eBPF check

# Scan a PKGBUILD / *.install / .SRCINFO for markers
scripts/review-pkgbuild.sh ~/.cache/pikaur/build/somepkg
```

**Exit codes**
- `scan-iocs.sh`: `0` clean · `1` needs attention / a check was skipped (e.g. eBPF
  without sudo) · `2` indicators found.
- `review-pkgbuild.sh`: `0` no markers · `1` REVIEW (runs a toolchain/fetcher/
  obfuscation/checksum-skip — eyeball it) · `2` HIGH-risk · `64` could not scan
  (treat as UNKNOWN, not safe).

> Without `sudo`, the eBPF check is reported `SKIPPED` (not a failure), so a
> healthy host returns `0`. The eBPF rootkit check only looks for three known map
> names — a clean result does not prove absence of a rootkit.

**Environment knobs** (`scan-iocs.sh`)

| Var | Default | Purpose |
|-----|---------|---------|
| `WINDOW_START` | `2026-06-09` | start of the incident date window |
| `WINDOW_END` | **today** | end of the window (tracks the run date) |
| `AUR_LIST_URL` | lenucksi raw list | override the compromised-name list source |
| `AUR_SAFE_ALLOW` | *(empty)* | space-separated names to silence (also reads `~/.config/aur-safe-update/allow.txt`) |

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
