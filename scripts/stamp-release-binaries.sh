#!/bin/bash
# Rewrites the RELEASE-BINARY-TARGET block in Package.swift so the binary
# target points at GitHub release assets instead of locally built artifacts.
# Used by the release workflow; the result is committed only on release tags.
#
# Usage: stamp-release-binaries.sh <version> <xcframework_sha256> <artifactbundle_sha256>
set -euo pipefail

VERSION="$1"
XCFRAMEWORK_CHECKSUM="$2"
ARTIFACTBUNDLE_CHECKSUM="$3"
REPO_URL="${REPO_URL:-https://github.com/samcat116/swift-cedar}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/Package.swift"

BLOCK=$(cat <<EOF
#if os(Linux)
let cedarFFIBinaryTarget: Target = .binaryTarget(
    name: "CedarFFIBinary",
    url: "$REPO_URL/releases/download/v$VERSION/CedarFFI.artifactbundle.zip",
    checksum: "$ARTIFACTBUNDLE_CHECKSUM"
)
#else
let cedarFFIBinaryTarget: Target = .binaryTarget(
    name: "CedarFFIBinary",
    url: "$REPO_URL/releases/download/v$VERSION/CedarFFI.xcframework.zip",
    checksum: "$XCFRAMEWORK_CHECKSUM"
)
#endif
EOF
)

export BLOCK
python3 - "$MANIFEST" <<'PY'
import os, sys

path = sys.argv[1]
block = os.environ["BLOCK"]
begin = "// RELEASE-BINARY-TARGET-BEGIN"
end = "// RELEASE-BINARY-TARGET-END"

lines = open(path).read().splitlines(keepends=True)
out, skipping, replaced = [], False, False
for line in lines:
    if begin in line:
        out.append(line)
        out.append(block + "\n")
        skipping, replaced = True, True
    elif end in line:
        out.append(line)
        skipping = False
    elif not skipping:
        out.append(line)

if not replaced or skipping:
    sys.exit(f"error: marker block not found or unterminated in {path}")
open(path, "w").write("".join(out))
PY

echo "==> stamped $MANIFEST for v$VERSION"
