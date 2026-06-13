#!/usr/bin/env bash
#
# review-sources.sh — fetch and scan a PKGBUILD's source=() trees for build/
# install-time code the PKGBUILD scan can't see: npm/JS lifecycle hooks, the
# campaign's IOC deps in manifests/lockfiles, and obvious shell droppers.
#
# It DOWNLOADS sources read-only (git clone --depth 1 / archive extract) and
# NEVER runs build()/prepare() or any install hook. Sources over a size cap, and
# binary artifacts (-bin packages), are skipped — this targets *source* recipes.
#
# Usage:   review-sources.sh <pkgbuild-dir> [more dirs...]
# Env:     AUR_SAFE_SRC_MAXBYTES (default 25 MiB) — per-source download cap
# Exit:    0 nothing · 1 REVIEW (lifecycle hook present) · 2 HIGH (IOC dep / dropper)
set -uo pipefail

[[ $# -eq 0 ]] && { echo "usage: $0 <pkgbuild-dir> [...]" >&2; exit 64; }

MAXBYTES="${AUR_SAFE_SRC_MAXBYTES:-26214400}"
IOC='atomic-lockfile|js-digest'
TMPROOT="$(mktemp -d)"; trap 'rm -rf "$TMPROOT"' EXIT
rc=0; bump(){ [[ $1 -gt $rc ]] && rc=$1; }
short(){ printf '%s' "${1#"$TMPROOT"/}"; }

scan_tree(){            # $1 = extracted/cloned dir
  local d=$1 pj lf hit
  # npm/JS lifecycle hooks (run automatically on npm/bun/yarn/pnpm install)
  while IFS= read -r pj; do
    if grep -aEq '"(preinstall|install|postinstall|prepare|prepublish|postprepare)"[[:space:]]*:' "$pj" 2>/dev/null; then
      echo "    [REVIEW] install/lifecycle script in $(short "$pj"):"
      grep -aEn '"(preinstall|install|postinstall|prepare|prepublish|postprepare)"[[:space:]]*:' "$pj" | sed 's/^/        /'
      bump 1
    fi
    grep -aEq "\"($IOC)\"[[:space:]]*:" "$pj" 2>/dev/null && { echo "    [HIGH] IOC dependency in $(short "$pj")"; bump 2; }
  done < <(find "$d" -name package.json -not -path '*/node_modules/*' 2>/dev/null)
  # IOC names anywhere in a lockfile
  while IFS= read -r lf; do
    grep -aEq "($IOC)" "$lf" 2>/dev/null && { echo "    [HIGH] IOC in lockfile $(short "$lf")"; bump 2; }
  done < <(find "$d" \( -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name bun.lockb \) 2>/dev/null)
  # dropper-style exec in source scripts / build manifests (no eval — too noisy in JS)
  hit=$(grep -aErnEi '/dev/(tcp|udp)/|base64[[:space:]]+--?de|(curl|wget)[^|]*\|[[:space:]]*(/[^|[:space:]]*/)?(ba)?sh\b' "$d" \
        --include='*.sh' --include='*.bash' --include='*.zsh' --include='Makefile' --include='*.mk' \
        --include='*.py' --include='*.js' --include='*.cjs' --include='*.mjs' --include='*.ts' 2>/dev/null | head -10)
  [[ -n "$hit" ]] && { echo "    [HIGH] dropper-style exec in source:"; sed 's/^/        /' <<<"$hit"; bump 2; }
}

fetch_and_scan(){       # $1 = raw source entry (name::url or url)
  local entry=$1 url name dest g
  if [[ "$entry" == *::* ]]; then name="${entry%%::*}"; url="${entry#*::}"; else url="$entry"; name="$(basename "${entry%%#*}")"; fi
  dest="$TMPROOT/$(printf '%s' "$name$url" | tr -c 'A-Za-z0-9' _ | cut -c1-72)"
  if [[ "$url" == git+* || "$url" == *.git || "$url" == *.git#* || "$url" == git://* ]]; then
    g="${url#git+}"; g="${g%%#*}"
    echo "  · git source: $url"
    if timeout 90 git clone --depth 1 -q "$g" "$dest" 2>/dev/null; then scan_tree "$dest"; else echo "    (clone failed/skipped)"; bump 1; fi
  elif [[ "$url" == http://* || "$url" == https://* || "$url" == ftp://* ]]; then
    case "${url%%#*}" in
      *.tar|*.tar.*|*.tgz|*.tbz2|*.txz|*.zip|*.crate|*.gem|*.whl)
        echo "  · archive source: $url"; mkdir -p "$dest"
        if timeout 90 curl -fsSL --max-filesize "$MAXBYTES" "${url%%#*}" -o "$dest/a" 2>/dev/null; then
          ( cd "$dest" && { tar xf a 2>/dev/null || unzip -qq a 2>/dev/null || true; } ); scan_tree "$dest"
        else echo "    (download skipped — over ${MAXBYTES}B cap or unreachable)"; fi ;;
      *) echo "  · skipped binary/non-archive source: $url" ;;
    esac
  fi  # local files are covered by review-pkgbuild.sh
}

for arg in "$@"; do
  pb="$(find "$arg" -maxdepth 2 -name PKGBUILD -print -quit 2>/dev/null)"
  sri="$(find "$arg" -maxdepth 2 -name .SRCINFO -print -quit 2>/dev/null)"
  [[ -z "$pb$sri" ]] && { echo "No PKGBUILD/.SRCINFO under: $arg" >&2; continue; }
  echo "### sources for $(basename "$(dirname "${pb:-$sri}")")"
  # prefer .SRCINFO (clean, no bash eval); fall back to a crude PKGBUILD source= grep
  if [[ -n "$sri" ]]; then
    mapfile -t SRCS < <(grep -aE '^[[:space:]]*source(_[a-z0-9_]+)?[[:space:]]*=' "$sri" | sed -E 's/^[^=]*=[[:space:]]*//')
  else
    mapfile -t SRCS < <(sed -nE '/source=\(/,/\)/p' "$pb" | grep -aoE '[a-z0-9_]*::?[^ "'"'"')]+' | grep -E '://|\.git')
  fi
  if [[ ${#SRCS[@]} -eq 0 ]]; then echo "  (no remote sources)"; continue; fi
  for s in "${SRCS[@]}"; do [[ -n "$s" ]] && fetch_and_scan "$s"; done
done

case $rc in
  0) echo "review-sources: no source-side markers (still advisory — sources can hide intent)." ;;
  1) echo "review-sources: REVIEW — source defines install/lifecycle hooks; read them." ;;
  2) echo "review-sources: HIGH — IOC dependency or dropper in the fetched source." ;;
esac
exit $rc
