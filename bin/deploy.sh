#!/usr/bin/env bash
#
# Copy the working tree into the local WordPress install for testing.
#
# The plugin is not symlinked from the developer's home directory: the
# permissions there stop the web server traversing into it, and the plugin
# then silently never loads over HTTP while still working under WP-CLI.
#
set -euo pipefail

SLUG="takumi-private-gate"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${PRVGATE_WP_PLUGINS:-/var/www/html/wp-content/plugins}/${SLUG}"

mkdir -p "${TARGET}"

rsync -a --delete \
	--exclude '.git' \
	--exclude '.gitignore' \
	--exclude 'bin/' \
	--exclude 'dist/' \
	--exclude '*.md' \
	--exclude 'languages/*.po' \
	--exclude 'languages/*.mo' \
	"${ROOT}/" "${TARGET}/"

# The web server runs as a different account than the developer.
chmod -R o+rX "${TARGET}"

echo "Deployed $(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo 'working tree') to ${TARGET}"
