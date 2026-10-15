#!/bin/sh
# SPDX-FileCopyrightText: 2026 contributors to cbom-netscan
# SPDX-License-Identifier: Apache-2.0

# sbom.sh ARCHIVE DOCUMENT VERSION
#
# Writes a CycloneDX 1.6 SBOM of a release archive to DOCUMENT with syft,
# matching the CycloneDX version cbom-netscan itself emits. GoReleaser runs
# it from dist/ for every archive (.goreleaser.yaml, sboms).
#
# The SBOM's subject is named cbom-netscan at VERSION (--source-name,
# --source-version) instead of the archive file name. syft unpacks the
# archive into a random temporary directory and names the files it finds by
# that path (/tmp/syft-archive-contents-NNN/cbom-netscan); the directory is
# stripped, so the binary is listed by its name in the archive and keeps its
# hashes.
set -eu

if [ $# -ne 3 ]; then
	echo "usage: $0 ARCHIVE DOCUMENT VERSION" >&2
	exit 2
fi
archive=$1
document=$2
version=$3
command -v jq >/dev/null || { echo "sbom.sh: jq is required" >&2; exit 1; }

syft "$archive" --quiet --source-name cbom-netscan --source-version "$version" \
	--output "cyclonedx-json@1.6=$document"

jq '(.. | strings) |= sub("^/.*/syft-archive-contents-[0-9]+/"; "")' "$document" >"$document.tmp"
mv "$document.tmp" "$document"
if grep -q 'syft-archive-contents-' "$document"; then
	echo "sbom.sh: a temporary path is left in $document" >&2
	exit 1
fi
