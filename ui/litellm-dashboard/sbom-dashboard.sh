#!/bin/bash
set -e

# Install CycloneDX Node module if not present
yarn global add @cyclonedx/cyclonedx-npm@4.0.0 || npm install -g @cyclonedx/cyclonedx-npm@4.0.0

# Generate SBOM for the dashboard (CycloneDX JSON v1.6)
cyclonedx-npm --output-file dashboard-sbom.json --output-format JSON --sv 1.6

echo "Dashboard SBOM generated: dashboard-sbom.json"
