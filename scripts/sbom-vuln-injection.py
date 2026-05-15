#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if len(sys.argv) != 4:
    print(
        "Usage: sbom-vuln-injection.py <original_sbom.json> <vulnerability_report.json> <output.json>"
    )
    sys.exit(1)

orig_path = Path(sys.argv[1])
scan_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])

# Load both JSON files
with orig_path.open() as f:
    sbom = json.load(f)

with scan_path.open() as f:
    report = json.load(f)


def _build_component_index(sbom: dict) -> dict:
    index: dict = {}

    def _register(component: dict, parent_ref: str = "") -> None:
        bom_ref = component.get("bom-ref") or (
            f"{parent_ref}|{component.get('name', '')}@{component.get('version', '')}"
        )
        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")

        if bom_ref:
            index.setdefault(("bom-ref", bom_ref), component)
        if purl:
            index.setdefault(("purl", purl), component)
        if name:
            index.setdefault(("name", name.lower(), version), component)
            index.setdefault(("name-only", name.lower()), component)

        for nested in component.get("components", []):
            _register(nested, bom_ref)

    for component in sbom.get("components", []):
        _register(component)

    return index


def _lookup_component(component_index: dict, package_name: str, package_version: str = "") -> dict | None:
    if package_name and package_version:
        candidate = component_index.get(("name", package_name.lower(), package_version))
        if candidate:
            return candidate

    if package_name:
        return component_index.get(("name-only", package_name.lower()))

    return None


def _extract_gitlab_vulnerabilities(report_json: dict, component_index: dict) -> list[dict]:
    vuln_entries: list[dict] = []

    for vuln in report_json.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue

        scanner = vuln.get("scanner", {}) if isinstance(vuln.get("scanner"), dict) else {}
        location = vuln.get("location", {}) if isinstance(vuln.get("location"), dict) else {}
        dependency = (
            location.get("dependency", {}) if isinstance(location.get("dependency"), dict) else {}
        )
        package = dependency.get("package", {}) if isinstance(dependency.get("package"), dict) else {}

        package_name = package.get("name") or dependency.get("name") or location.get("package") or ""
        package_version = package.get("version") or dependency.get("version") or ""

        matched_component = _lookup_component(component_index, package_name, package_version)
        affects_ref = ""
        if matched_component:
            affects_ref = matched_component.get("purl") or matched_component.get("bom-ref", "")
        if not affects_ref:
            affects_ref = package_name

        identifiers = vuln.get("identifiers", [])
        advisory_urls = []
        for identifier in identifiers:
            if not isinstance(identifier, dict):
                continue
            url = identifier.get("url")
            if url:
                advisory_urls.append({"url": url})

        references = vuln.get("links", [])
        for link in references:
            if link:
                advisory_urls.append({"url": link})

        ratings = []
        severity = vuln.get("severity", "")
        if severity:
            ratings.append(
                {
                    "source": {"name": scanner.get("name", "GitLab Dependency Scanning")},
                    "method": "severity",
                    "score": None,
                    "severity": severity,
                }
            )

        vuln_obj = {
            "id": vuln.get("id") or vuln.get("message") or vuln.get("name"),
            "source": {
                "name": scanner.get("name", "GitLab Dependency Scanning"),
                "url": scanner.get("url", ""),
            },
            "description": vuln.get("description") or vuln.get("message") or "",
            "ratings": ratings,
            "affects": [{"ref": affects_ref}],
        }

        solution = vuln.get("solution")
        if solution:
            vuln_obj["analysis"] = {"state": "needs-triage", "detail": solution}

        if advisory_urls:
            vuln_obj["advisories"] = advisory_urls

        vuln_entries.append(vuln_obj)

    return vuln_entries


def _extract_grype_vulnerabilities(report_json: dict) -> list[dict]:
    vuln_entries: list[dict] = []

    for match in report_json.get("matches", []):
        vuln = match.get("vulnerability", {})
        related = match.get("relatedVulnerabilities", [])
        artifact = match.get("artifact", {})

        purl = artifact.get("purl") or artifact.get("id") or ""
        if not purl:
            continue

        vuln_obj = {
            "id": vuln.get("id"),
            "source": {
                "name": vuln.get("namespace", "Grype"),
                "url": vuln.get("dataSource", ""),
            },
            "description": vuln.get("description", ""),
            "ratings": [],
            "affects": [{"ref": purl}],
        }

        for rel in related:
            for cvss in rel.get("cvss", []):
                rating = {
                    "source": {"name": cvss.get("source", "")},
                    "method": cvss.get("version", ""),
                    "score": cvss.get("metrics", {}).get("baseScore"),
                    "severity": rel.get("severity", ""),
                }
                vuln_obj["ratings"].append(rating)

        urls = []
        for rel in related:
            for url in rel.get("urls", []):
                urls.append({"url": url})
        if urls:
            vuln_obj["advisories"] = urls

        vuln_entries.append(vuln_obj)

    return vuln_entries

component_index = _build_component_index(sbom)

if "matches" in report:
    vuln_entries = _extract_grype_vulnerabilities(report)
else:
    vuln_entries = _extract_gitlab_vulnerabilities(report, component_index)

# Insert vulnerabilities into SBOM
existing_vulns = sbom.get("vulnerabilities", [])
sbom["vulnerabilities"] = existing_vulns + vuln_entries

# Write merged SBOM
out_path.parent.mkdir(parents=True, exist_ok=True)
with out_path.open("w") as f:
    json.dump(sbom, f, indent=2)

print(f"✅ Merged {len(vuln_entries)} vulnerabilities into {orig_path.name} → {out_path.name}")