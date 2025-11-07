#!/bin/sh
#
# Install documentation files for microsocks and msadmin
#
set -e

DOCDIR="${1:-/usr/local/share/doc/microsocks}"
MODE="${2:-644}"
VERBOSE="${3:-1}"

vecho() {
    test "$VERBOSE" = "1" && echo "$@"
}

mkdir -p "$DOCDIR"
umask 022

# ensure DOCDIR exists and has correct perms
chmod 755 "$DOCDIR"

# install markdown docs
for doc in MIGRATION.md; do
    vecho "Installing $doc -> $DOCDIR"
    cp "$doc" "$DOCDIR/"
    chmod "$MODE" "$DOCDIR/$doc"
done

vecho "Documentation installed in $DOCDIR"
exit 0