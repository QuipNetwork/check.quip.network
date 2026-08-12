#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Fetch the dnsimple-certifier source that Dockerfile.tls builds the `certifier`
# CLI from.
#
# dnsimple-certifier lives in a separate private repo and is not vendored here,
# so `docker build -f Dockerfile.tls` cannot work from a clean clone until this
# has run. Building from source is required: the published dnsimple-certifier
# image ships only the server binary (`dnsimple-certifier`), not the `certifier`
# CLI that entrypoint.sh calls.
#
# Pinned by ref so the image is reproducible. Override with CERTIFIER_REF.

set -eu

REF="${CERTIFIER_REF:-v0.1.0}"
REPO="${CERTIFIER_REPO:-git@gitlab-quip:quip.network/dnsimple-certifier.git}"
DEST="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/dnsimple-certifier"

if [ -d "$DEST/.git" ]; then
    git -C "$DEST" fetch --tags --quiet origin
else
    rm -rf "$DEST"
    git clone --quiet "$REPO" "$DEST"
fi

git -C "$DEST" checkout --quiet --detach "$REF"

# Fail closed: assert we are on the pinned ref and the CLI source is actually
# there, rather than letting the build fall through to a stale checkout.
resolved="$(git -C "$DEST" rev-parse HEAD)"
expected="$(git -C "$DEST" rev-parse "${REF}^{commit}")"
if [ "$resolved" != "$expected" ]; then
    echo "fetch-certifier: HEAD is $resolved, expected $REF ($expected)" >&2
    exit 1
fi
if [ ! -f "$DEST/cmd/certifier/main.go" ]; then
    echo "fetch-certifier: cmd/certifier/ missing at $REF" >&2
    exit 1
fi

echo "dnsimple-certifier pinned at $REF ($resolved)"
