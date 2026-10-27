"""Local Trivy report import and a fail-closed Docker network-none image scan."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .core import Finding

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def import_report(document, source_hash, label="local-image"):
    if (not isinstance(document, dict) or type(document.get("SchemaVersion")) is not int
            or document["SchemaVersion"] != 2 or not isinstance(document.get("Results"), list)):
        raise ValueError("Expected a Trivy schema-2 JSON report with Results")
    findings = {}
    for result_index, result in enumerate(document["Results"]):
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Invalid vulnerability list")
        for index, value in enumerate(vulnerabilities):
            if not isinstance(value, dict):
                raise ValueError("Invalid vulnerability entry")
            vid = value.get("VulnerabilityID")
            pkg = value.get("PkgName")
            installed = value.get("InstalledVersion")
            if not all(isinstance(x, str) and 0 < len(x) < 1000 for x in (vid, pkg, installed)):
                raise ValueError("Vulnerability ID, package and installed version are required")
            severity = value.get("Severity", "UNKNOWN")
            if severity not in SEVERITIES:
                severity = "UNKNOWN"
            fixed = value.get("FixedVersion")
            advice = ("Review and test an upgrade to the scanner-reported fixed version: " + str(fixed)
                      if fixed else "No fixed version reported. Review applicability, mitigations and the advisory offline.")
            evidence = f"/Results/{result_index}/Vulnerabilities/{index}: {vid}; package={pkg}; installed={installed}"
            finding = Finding("TRIVY-" + vid, severity, label, "Scanner-reported known package vulnerability",
                              evidence, advice, category="known-vulnerability").to_dict()
            findings[finding["id"]] = finding
    report = {"schema": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "assessment": "REVIEW_REQUIRED" if findings else "NO_FINDINGS_IN_CHECKED_SCOPE",
            "coverage": {"status": "PARTIAL", "source_sha256": source_hash,
                         "scanner": "Trivy report import", "result_sections": len(document["Results"]),
                         "limitations": ["Imported scanner output is not independently authenticated.",
                                         "Database age and scan completion cannot be established from an arbitrary imported report.",
                                         "Package vulnerability matches do not establish runtime exploitability.",
                                         "Kubernetes configuration, reachability and effective permissions were not assessed by this input."]},
            "findings": list(findings.values())}
    if document.get("_fixture") is True:
        report["coverage"]["limitations"].insert(0, "SYNTHETIC EXAMPLE: this input is not a real vulnerability scan.")
    return report


def invoke(args, runner=None, timeout=30):
    try:
        if runner is not None:
            result = runner(args, capture_output=True, text=True, timeout=timeout, check=False)
            raw = result.stdout
        else:
            # Spool large scanner output to a private temporary file, not unbounded RAM.
            with tempfile.TemporaryFile() as spool:
                result = subprocess.run(args, stdout=spool, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
                spool.seek(0)
                data = spool.read(32 * 1024 * 1024 + 1)
            if len(data) > 32 * 1024 * 1024:
                raise ValueError("Local scanner output exceeded the size budget")
            raw = data.decode("utf-8")
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Local scanner operation failed; no network fallback attempted") from None
    if result.returncode:
        raise ValueError("Local scanner operation failed; inspect tool compatibility and offline prerequisites")
    return raw


def local_engine(runner=None):
    endpoint = os.environ.get("DOCKER_HOST")
    if not endpoint:
        context = json.loads(invoke(["docker", "context", "inspect"], runner))
        endpoint = context[0]["Endpoints"]["docker"]["Host"]
    if not isinstance(endpoint, str) or not endpoint.startswith(("unix://", "npipe://")):
        raise ValueError("Only a local Unix socket or Windows named-pipe Docker engine is permitted")
    return ["docker", "--host", endpoint]


def validate_path(path, *, directory=False):
    path = Path(path).resolve()
    if (not path.is_dir() if directory else not path.is_file()) or any(c in str(path) for c in ",\n\r"):
        raise ValueError("Missing or unsupported local input path")
    return path


def database_info(cache):
    db = cache / "db/trivy.db"
    metadata = cache / "db/metadata.json"
    if not db.is_file() or not metadata.is_file():
        raise ValueError("Provide a populated cache containing db/trivy.db and db/metadata.json")
    raw = metadata.read_bytes()
    value = json.loads(raw)
    stamp = value.get("UpdatedAt")
    if not isinstance(stamp, str):
        raise ValueError("Vulnerability database UpdatedAt is missing")
    updated = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if updated.tzinfo is None:
        raise ValueError("Database timestamp must include timezone")
    age = (datetime.now(timezone.utc) - updated).total_seconds() / 86400
    if age < -1:
        raise ValueError("Database timestamp is in the future")
    hasher = hashlib.sha256()
    with db.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return {"updated_at": stamp, "age_days": round(max(0, age), 2),
            "metadata_sha256": hashlib.sha256(raw).hexdigest(), "db_sha256": hasher.hexdigest(),
            "authenticity": "not verified; operator must verify the imported update bundle"}


def build_command(engine, scanner_image, archive, cache):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-fA-F0-9]{64}", scanner_image):
        raise ValueError("Scanner image must be pinned to an approved SHA-256 digest")
    script = ("mkdir -p /tmp/trivy-cache && cp -R /offline-db/. /tmp/trivy-cache/ && "
              "exec trivy image --config /dev/null --input /scan/image.tar --cache-dir /tmp/trivy-cache "
              "--scanners vuln --format json --skip-db-update --skip-java-db-update --offline-scan "
              "--skip-check-update --skip-version-check --disable-telemetry")
    return [*engine, "run", "--rm", "--pull=never", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128",
            "--memory=1g", "--cpus=1", "--user=65532:65532",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=2g",
            "--mount", f"type=bind,src={archive.as_posix()},dst=/scan/image.tar,readonly",
            "--mount", f"type=bind,src={cache.as_posix()},dst=/offline-db,readonly",
            "--entrypoint=/bin/sh", scanner_image, "-c", script]


def scan_image(archive, cache, scanner_image, runner=None):
    archive = validate_path(archive)
    cache = validate_path(cache, directory=True)
    metadata = database_info(cache)
    engine = local_engine(runner)
    # The engine must already have this exact image. Do not download anything.
    command = build_command(engine, scanner_image, archive, cache)
    invoke([*engine, "image", "inspect", scanner_image], runner)
    raw = invoke(command, runner, timeout=300)
    if len(raw.encode()) > 32 * 1024 * 1024:
        raise ValueError("Scanner output exceeded 32 MiB")
    report = import_report(json.loads(raw), hashlib.sha256(raw.encode()).hexdigest())
    report["coverage"].update(scanner="Network-isolated local Trivy container", scanner_image=scanner_image,
                              database=metadata, network_mode="none", pull_policy="never")
    report["coverage"]["limitations"][0] = "Operator must trust the digest-pinned scanner image and imported database; hashes are not signatures."
    report["coverage"]["limitations"][1] = "Vulnerability coverage depends on the imported database, scanner support and the supplied archive."
    if metadata["age_days"] > 7:
        report["coverage"]["limitations"].append("Database is older than seven days; recent advisories may be missing.")
    return report
