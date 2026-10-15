#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 contributors to cbom-netscan
# SPDX-License-Identifier: Apache-2.0

# release-notes.sh TAG REPO [CHANGELOG]
#
# Prints the release notes for TAG (vX.Y.Z): the "## [X.Y.Z]" section of
# CHANGELOG (default CHANGELOG.md), without its heading. Relative links are
# made absolute (https://github.com/REPO/blob/TAG/...), because the release
# page is not in the repository tree and a link like MAPPING.md would break
# there. Fails if the section is missing, still marked Unreleased, or empty
# apart from the tag name.
#
# Used by .github/workflows/release.yml; run it locally to preview:
#   .github/scripts/release-notes.sh v0.1.1 yechuri-github64/cbom-netscan
set -euo pipefail

if [ $# -lt 2 ]; then
	echo "usage: $0 TAG OWNER/REPO [CHANGELOG]" >&2
	exit 2
fi
tag="$1"
repo="$2"
changelog="${3:-CHANGELOG.md}"
version="${tag#v}"

fail() {
	echo "::error::$*" >&2
	exit 1
}

heading="$(grep -F -m1 "## [${version}]" "$changelog" || true)"
case "$heading" in
"") fail "${changelog} has no section for ${version}" ;;
*Unreleased*) fail "${changelog} still marks ${version} as Unreleased; set the release date first" ;;
esac

# The lines after the heading, up to the next "## [" heading.
body="$(awk -v h="## [${version}]" '
	index($0, h) == 1 { found = 1; next }
	found && /^## \[/ { exit }
	found { print }
' "$changelog")"

# Relative targets of inline links, "](MAPPING.md#x)", and of reference
# definitions, "[x]: docs/a.md", become absolute. Targets with a scheme (they
# contain ":"), anchors ("#..."), and absolute paths ("/...") are left alone.
base="https://github.com/${repo}/blob/${tag}/"
body="$(printf '%s\n' "$body" | sed -E \
	-e "s|\]\((\./)?([^)#:/][^):]*)\)|](${base}\2)|g" \
	-e "s|^(\[[^]]+\]:[[:space:]]+)(\./)?([^[:space:]#:/][^[:space:]:]*)\$|\1${base}\3|")"

trimmed="$(printf '%s' "$body" | tr -d '[:space:]')"
if [ -z "$trimmed" ] || [ "$trimmed" = "$tag" ] || [ "$trimmed" = "$version" ]; then
	fail "the ${version} section of ${changelog} is empty or only names the tag"
fi
printf '%s\n' "$body"
