#!/usr/bin/env bash
# SC-005: no secret material, seeds or share links in any captured output.
# The integration suite uses marker values (WARDEN-MARKER-PW-*, WARDEN-MARKER-SEED-*)
# for every password and seed it stores; a share link always contains
# /warden/share[/#]<43 chars>.
set -euo pipefail
ART="${ARTIFACTS:-.artifacts}"; export FREYA_CAPTURE_DIR="$ART/capture"; mkdir -p "$FREYA_CAPTURE_DIR"
go test -count=1 -tags integration ./tests/integration/... -run 'Test' -v > "$ART/integration.log" 2>&1 || { tail -50 "$ART/integration.log"; exit 1; }
cp "$ART/integration.log" "$FREYA_CAPTURE_DIR/suite.log"
n=0; for pat in 'WARDEN-MARKER-PW-' 'WARDEN-MARKER-SEED-' '/warden/share[/#][A-Za-z0-9_-]\{43\}' 'otpauth://' '-----BEGIN' 'eyJhbGciOiJFZERTQSI'; do
  c=$({ grep -rc -- "$pat" "$FREYA_CAPTURE_DIR" || true; } | awk -F: '{s+=$2} END {print s+0}'); echo "redaction-scan: '$pat': $c"; n=$((n+c)); done
[[ "$n" -eq 0 ]] || { echo "redaction-scan: FAIL ($n matches)" >&2; exit 1; }; echo "redaction-scan: 0 matches"
