#!/bin/bash
set -e

SBOM_JSON=$1
VULN_JSON=$2
OUT_JSON=$3

# If either file is missing, exit
if [ ! -f "$SBOM_JSON" ]; then
  echo "SBOM JSON not found: $SBOM_JSON"; exit 1
fi
if [ ! -f "$VULN_JSON" ]; then
  echo "Vulnerability JSON not found: $VULN_JSON"; exit 1
fi

python3 scripts/sbom-vuln-injection.py "$SBOM_JSON" "$VULN_JSON" "$OUT_JSON"
