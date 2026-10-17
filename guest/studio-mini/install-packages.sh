#!/bin/sh
# Runs inside the digest-pinned builder with --network=none.
set -eu
cd /package-inputs
sha256sum -c SHA256SUMS
set -- ./*.apk
test -f "$1"
# SHA-256 binds the reviewed bytes; Alpine's keys authenticate their publisher.
apk verify "$@"
apk --no-network --repositories-file /dev/null add "$@"
apk info -vv | sort > /etc/squirrelops-guest-packages.txt
diff -u /tmp/squirrelops-packages.lock /etc/squirrelops-guest-packages.txt
# File-based installation must not turn every dependency into a top-level
# request in the attacker-visible package database. Restore the reviewed world.
cp /tmp/squirrelops-packages.world /etc/apk/world
rm /tmp/squirrelops-packages.world
