#!/bin/bash
set -e

# Install CycloneDX Node module if not present
yarn global add @cyclonedx/bom@3.11.0 || npm install -g @cyclonedx/bom@3.11.0

# Generate SBOM for the dashboard (CycloneDX JSON v1.6)
cyclonedx-bom -o dashboard-sbom.json --output-format json:v1.6

echo "Dashboard SBOM generated: dashboard-sbom.json"
