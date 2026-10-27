"""Local workflow entry point. No live cluster access or automatic update path."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

from .core import audit_snapshot, load_json
from .report import write_existing, write_report
from .trivy import import_report, scan_image


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline environment audit: evidence, findings and explicit coverage")
    sub = parser.add_subparsers(dest="command", required=True)
    k8s = sub.add_parser("audit-k8s")
    k8s.add_argument("snapshot")
    imported = sub.add_parser("import-trivy")
    imported.add_argument("report")
    scanned = sub.add_parser("scan-image")
    scanned.add_argument("archive")
    scanned.add_argument("--cache", required=True)
    scanned.add_argument("--scanner-image", required=True)
    scanned.add_argument("--allow-local-container", action="store_true")
    for p in (k8s, imported, scanned):
        p.add_argument("--output", required=True)
        p.add_argument("--fail-on", choices=("HIGH", "CRITICAL"))
    args = parser.parse_args(argv)
    scan_dir = None
    try:
        if args.command == "audit-k8s":
            document, sha = load_json(args.snapshot)
            report = audit_snapshot(document, sha)
        elif args.command == "import-trivy":
            document, sha = load_json(args.report)
            report = import_report(document, sha)
        else:
            if not args.allow_local_container:
                raise ValueError("Local scanner execution requires --allow-local-container")
            candidate = Path(args.output)
            candidate.mkdir(parents=True, exist_ok=False)
            scan_dir = candidate
            report = scan_image(args.archive, args.cache, args.scanner_image)
        if scan_dir is not None:
            write_existing(scan_dir, report)
        else:
            write_report(args.output, report)
        print(f"Report: {Path(args.output).resolve() / 'report.html'}")
        print(f"Assessment: {report['assessment']}; coverage: {report['coverage']['status']}; findings: {len(report['findings'])}")
        blocked = {"CRITICAL"} if args.fail_on == "CRITICAL" else {"HIGH", "CRITICAL"} if args.fail_on else set()
        return 1 if any(f["severity"] in blocked for f in report["findings"]) else 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, IndexError):
        if scan_dir is not None and not (scan_dir / "report.json").exists():
            failure = {"schema": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
                       "assessment": "SCAN_ERROR", "coverage": {"status": "ERROR", "limitations": [
                           "Scan did not complete. Check local engine, scanner compatibility, image archive and imported database.",
                           "No conclusion about vulnerabilities can be drawn from this failed scan."]}, "findings": []}
            write_existing(scan_dir, failure)
        print("Audit failed: check input format, new output path and offline prerequisites. No network fallback was attempted.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
