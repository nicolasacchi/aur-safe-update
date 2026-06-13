# aur-safe-update

A [Claude Code](https://claude.com/claude-code) **skill** that performs a full
Arch Linux system update — official repos **plus** the AUR — behind a
supply-chain safety gate.

Official repositories (`[core]/[extra]/[multilib]`) are signed and trusted. The
AUR is not: any maintainer (or anyone who adopts an orphaned package) can put
arbitrary code in a `PKGBUILD` that runs at build/install time. This skill makes
that step reviewable instead of automatic.

> Built in response to the **June 2026 `atomic-lockfile` AUR campaign**, in which
> ~1,500 orphaned AUR packages were hijacked to ship an infostealer + eBPF
> rootkit via a malicious `npm`/`bun` install hook.

## What it does

1. **Pre-flight sweep** — IOC scan (eBPF rootkit maps, suspicious systemd
   persistence, `atomic-lockfile`/`js-digest` npm/bun artifacts) and a
   **provides-aware** cross-check of installed packages against the
   known-compromised list. Aborts the update if the host shows indicators.
2. **Official repos** — preview via `checkupdates`, then `sudo pacman -Syu`.
3. **AUR gate** — for every pending AUR update, fetch the *incoming* `PKGBUILD`
   straight from the AUR, scan it for malware markers, and diff it against the
   last recipe that was built, so you see exactly what changed.
4. **Apply** — only after explicit approval; holds anything with HIGH-risk
   markers; never `--noconfirm` on AUR builds.
5. **Post-update sweep** — re-runs the IOC scan to confirm a clean result.

The **PKGBUILD diff review is the permanent, campaign-agnostic defense** — it
relies on no known-bad list and keeps working after this incident is over. The
list cross-check is a removable "incident layer."

## Install

```bash
git clone https://github.com/nicolasacchi/aur-safe-update.git ~/.claude/skills/aur-safe-update
chmod +x ~/.claude/skills/aur-safe-update/scripts/*.sh
```

Then in Claude Code, just ask to update your system, or run `/aur-safe-update`.

> The skill self-identifies as `safe-update` via its `SKILL.md` frontmatter;
> the directory/repo name is `aur-safe-update`. Clone into whichever directory
> name you prefer — Claude reads the `name:` field, not the folder.

## Prerequisites

- [`pikaur`](https://github.com/actionless/pikaur) (the AUR helper this targets;
  adapt the commands for `yay`/`paru`)
- `pacman-contrib` (provides `checkupdates`)
- `curl`

## Using the scripts standalone

Both scripts work without Claude — handy in CI or a cron healthcheck.

```bash
# IOC sweep + provides-aware compromised-list cross-check
scripts/scan-iocs.sh --fetch              # fetch the live community list
scripts/scan-iocs.sh --list ./list.txt    # or use a local list
sudo scripts/scan-iocs.sh --fetch         # sudo => also reads /sys/fs/bpf (eBPF check)

# Scan a PKGBUILD / *.install / .SRCINFO for malware markers
scripts/review-pkgbuild.sh ~/.cache/pikaur/build/somepkg
```

`scan-iocs.sh` exit codes: `0` clean · `1` needs attention/partial · `2` indicators found.
`review-pkgbuild.sh` exit codes: `0` clean · `1` informational only · `2` HIGH-risk markers.

### Why "provides-aware" matters

`pacman -Qmq <name>` resolves `provides`, so a `-bin` package can match a listed
*source* package name (e.g. `stripe-cli-bin` provides `stripe-cli`). The scanner
labels that case `PROVIDE-ALIAS` (likely false positive — verify the binary)
rather than reporting it as a direct hit.

## Incident references

- Authoritative live list: <https://md.archlinux.org/s/SxbqukK6IA>
- Community detection repo: <https://github.com/lenucksi/aur-malware-check>

## Disclaimer

A safety aid, not a guarantee. It reduces the risk of building a poisoned AUR
package; it cannot prove a package is safe. Review the diffs it shows you. No
warranty — see [LICENSE](LICENSE).
