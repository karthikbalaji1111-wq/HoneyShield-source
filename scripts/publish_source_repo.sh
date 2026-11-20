#!/usr/bin/env bash
# Copies the complete source of this checkout into a clone of the public repository
# HoneyShield-source, replacing what was there (its .git is kept). Every tracked file is copied
# except the paths in deploy/public/EXCLUDE. Refuses if a personal email address or a local home
# path would be published. Used by the release workflow; can be run by hand:
#   git clone https://github.com/karthikbalaji1111-wq/HoneyShield-source.git /tmp/hss
#   git -C /tmp/hss config user.name "Karthik Balaji"
#   git -C /tmp/hss config user.email "karthikbalaji1111-wq@users.noreply.github.com"
#   scripts/publish_source_repo.sh /tmp/hss v1.3.1      # copy, commit and tag (no push)
#   git -C /tmp/hss push origin main v1.3.1
# Without a version it only copies and stages.
set -euo pipefail
DEST="${1:?usage: publish_source_repo.sh DEST_DIR [vX.Y.Z]}"
VERSION="${2:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXCLUDE="$ROOT/deploy/public/EXCLUDE"
[ -d "$DEST/.git" ] || { echo "error: $DEST is not a git clone" >&2; exit 1; }
if [ -n "$VERSION" ]; then
  case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "error: version must look like v1.2.3" >&2; exit 1 ;; esac
  if git -C "$DEST" rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
    echo "error: $VERSION is already published in $DEST" >&2; exit 1
  fi
fi

excluded() {  # excluded PATH: true when PATH matches a line of the exclude list
  local p line
  p="$1"
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in
      */) case "$p" in "$line"*) return 0 ;; esac ;;
      *) [ "$p" = "$line" ] && return 0 ;;
    esac
  done < "$EXCLUDE"
  return 1
}

# Start from an empty tree so deleted and newly excluded files disappear too.
git -C "$DEST" rm -rq --ignore-unmatch -- . >/dev/null
count=0
while IFS= read -r -d '' f; do
  excluded "$f" && continue
  mkdir -p "$DEST/$(dirname "$f")"
  cp -p "$ROOT/$f" "$DEST/$f"
  count=$((count + 1))
done < <(git -C "$ROOT" ls-files -z)

# Nothing personal may leave: no personal mailbox addresses, no macOS home paths.
if grep -rIlE '[A-Za-z0-9._%+-]+@(gmail|googlemail|icloud|me|mac|yahoo|outlook|hotmail|live|proton|protonmail)\.[a-z]+|/Users/[A-Za-z]' \
     --exclude-dir=.git "$DEST"; then
  echo "error: the files above contain a personal email address or a home path; nothing was staged or committed" >&2
  exit 1
fi

git -C "$DEST" add -A
echo "published $count files into $DEST"
[ -n "$VERSION" ] || exit 0
git -C "$DEST" diff --cached --quiet || git -C "$DEST" commit -q -m "HoneyShield ${VERSION#v}"
git -C "$DEST" tag -a "$VERSION" -m "HoneyShield ${VERSION#v}"
echo "committed and tagged $VERSION; push with: git -C $DEST push origin main $VERSION"
