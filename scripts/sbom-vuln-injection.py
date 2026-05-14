#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if len(sys.argv) != 4:
    print("Usage: sbom-vuln-injection.py <original_sbom.json> <grype_scan.json> <output.json>")
    sys.exit(1)

orig_path = Path(sys.argv[1])
scan_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])

# Load both JSON files
with orig_path.open() as f:
    sbom = json.load(f)

with scan_path.open() as f:
    grype = json.load(f)

# Build a lookup of vulnerabilities by component purl
vuln_entries = []
for match in grype.get("matches", []):
    vuln = match.get("vulnerability", {})
    related = match.get("relatedVulnerabilities", [])
    artifact = match.get("artifact", {})

    purl = artifact.get("purl")
    if not purl:
        continue

    # Basic vulnerability object
    vuln_obj = {
        "id": vuln.get("id"),
        "source": {
            "name": vuln.get("namespace", ""),
            "url": vuln.get("dataSource", "")
        },
        "description": vuln.get("description", ""),
        "ratings": [],
        "affects": [{"ref": purl}],
    }

    # Add CVSS scores from related vulnerabilities if available
    for rel in related:
        for cvss in rel.get("cvss", []):
            rating = {
                "source": {"name": cvss.get("source", "")},
                "method": cvss.get("version", ""),
                "score": cvss.get("metrics", {}).get("baseScore"),
                "severity": rel.get("severity", "")
            }
            vuln_obj["ratings"].append(rating)

    # Add advisory URLs
    urls = []
    for rel in related:
        for u in rel.get("urls", []):
            urls.append({"url": u})
    if urls:
        vuln_obj["advisories"] = urls

    vuln_entries.append(vuln_obj)

# Insert vulnerabilities into SBOM
existing_vulns = sbom.get("vulnerabilities", [])
sbom["vulnerabilities"] = existing_vulns + vuln_entries

# Write merged SBOM
out_path.parent.mkdir(parents=True, exist_ok=True)
with out_path.open("w") as f:
    json.dump(sbom, f, indent=2)

print(f"✅ Merged {len(vuln_entries)} vulnerabilities into {orig_path.name} → {out_path.name}")