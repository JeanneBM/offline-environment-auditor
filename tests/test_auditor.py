from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from offline_auditor.cli import main
from offline_auditor.core import audit_snapshot, load_json
from offline_auditor.report import render_html, write_report
from offline_auditor.trivy import build_command, database_info, import_report, local_engine, scan_image

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "aquasecurity/trivy@sha256:" + "a" * 64


def snapshot(items):
    return {"apiVersion": "v1", "kind": "List", "items": items}


def pod(security=None):
    return {"kind": "Pod", "metadata": {"namespace": "test", "name": "api"},
            "spec": {"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "api",
                      "image": "local.invalid/api@sha256:" + "a" * 64,
                      "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
                      "securityContext": security if security is not None else {
                          "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}}]}}


class RuleTests(unittest.TestCase):
    def test_restricted_pod_has_no_findings_but_not_complete_coverage(self):
        result = audit_snapshot(snapshot([pod()]), "test-sha")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["coverage"]["status"], "PARTIAL")
        self.assertNotIn("SECURE", result["assessment"])

    def test_privileged_container_is_reported_with_a_pointer(self):
        obj = pod({"privileged": True})
        result = audit_snapshot(snapshot([obj]), "test-sha")
        finding = next(f for f in result["findings"] if f["rule_id"] == "K8S-PRIVILEGED")
        self.assertIn("/spec/containers/0/securityContext/privileged", finding["evidence"])
        self.assertEqual(finding["severity"], "HIGH")

    def test_pod_nonroot_policy_is_inherited(self):
        result = audit_snapshot(snapshot([pod()]), "test-sha")
        self.assertFalse(any(f["rule_id"] == "K8S-NONROOT" for f in result["findings"]))

    def test_container_can_override_pod_nonroot_policy(self):
        obj = pod()
        obj["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] = False
        result = audit_snapshot(snapshot([obj]), "test-sha")
        self.assertTrue(any(f["rule_id"] == "K8S-NONROOT" for f in result["findings"]))

    def test_cronjob_template_and_init_container_are_checked(self):
        obj = {"kind": "CronJob", "metadata": {"name": "job"}, "spec": {"jobTemplate": {"spec": {
            "template": {"spec": {"initContainers": [{"image": "x", "securityContext": {"privileged": True}}]}}}}}}
        result = audit_snapshot(snapshot([obj]), "sha")
        finding = next(f for f in result["findings"] if f["rule_id"] == "K8S-PRIVILEGED")
        self.assertIn("/jobTemplate/spec/template/spec/initContainers/0", finding["evidence"])

    def test_secrets_env_and_annotations_are_not_exported(self):
        obj = pod()
        obj["metadata"]["annotations"] = {"private": "sensitive-annotation"}
        obj["spec"]["containers"][0]["env"] = [{"name": "PASSWORD", "value": "sensitive-env"}]
        secret = {"kind": "Secret", "data": {"token": "sensitive-secret"}}
        result = audit_snapshot(snapshot([obj, secret]), "sha")
        text = json.dumps(result)
        for value in ("sensitive-annotation", "sensitive-env", "sensitive-secret"):
            self.assertNotIn(value, text)
        self.assertEqual(result["coverage"]["secret_objects_excluded"], 1)

    def test_wildcard_role_does_not_claim_effective_access(self):
        obj = {"kind": "Role", "metadata": {"name": "role"}, "rules": [{"resources": ["*"], "verbs": ["get"]}]}
        finding = audit_snapshot(snapshot([obj]), "sha")["findings"][0]
        self.assertIn("effective bindings not evaluated", finding["title"])

    def test_duplicate_objects_are_deduplicated(self):
        obj = pod({"privileged": True})
        single = audit_snapshot(snapshot([obj]), "sha")["findings"]
        repeated = audit_snapshot(snapshot([obj, obj]), "sha")["findings"]
        self.assertEqual(single, repeated)

    def test_unsupported_kind_is_visible(self):
        report = audit_snapshot(snapshot([{"kind": "CustomResource"}]), "sha")
        self.assertIn("CustomResource", report["coverage"]["unsupported_kinds"])

    def test_windows_workload_is_explicitly_outside_ruleset(self):
        obj = pod({"privileged": True})
        obj["spec"]["os"] = {"name": "windows"}
        result = audit_snapshot(snapshot([obj]), "sha")
        self.assertEqual(result["findings"], [])
        self.assertIn("WindowsWorkload", result["coverage"]["unsupported_kinds"])

    def test_python_audit_path_never_opens_a_network_socket(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("subprocess.run", side_effect=AssertionError("subprocess forbidden")):
            document, sha = load_json(ROOT / "examples/k8s-snapshot.json")
            report = audit_snapshot(document, sha)
            self.assertTrue(report["findings"])
            self.assertIn("Offline environment audit", render_html(report))


class ReportTests(unittest.TestCase):
    def test_html_escapes_untrusted_resource_names(self):
        obj = pod({"privileged": True})
        obj["metadata"]["name"] = '<script>alert("x")</script>'
        text = render_html(audit_snapshot(snapshot([obj]), "sha"))
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("default-src 'none'", text)
        self.assertNotIn("<a ", text)

    def test_existing_report_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report"
            report = audit_snapshot(snapshot([]), "sha")
            write_report(output, report)
            with self.assertRaises(FileExistsError):
                write_report(output, report)

    def test_cli_produces_a_report_and_optional_gate_exit_code(self):
        with tempfile.TemporaryDirectory() as temp, patch("sys.stdout", new=io.StringIO()):
            result = main(["audit-k8s", str(ROOT / "examples/k8s-snapshot.json"),
                           "--output", str(Path(temp) / "report"), "--fail-on", "HIGH"])
            self.assertEqual(result, 1)
            self.assertTrue((Path(temp) / "report/report.html").exists())

    def test_bad_input_does_not_produce_a_success_report(self):
        with tempfile.TemporaryDirectory() as temp, patch("sys.stderr", new=io.StringIO()):
            path = Path(temp) / "bad.json"
            path.write_text('{"kind":"List","items":[null]}')
            result = main(["audit-k8s", str(path), "--output", str(Path(temp) / "out")])
            self.assertEqual(result, 2)
            self.assertFalse((Path(temp) / "out").exists())


class ScannerTests(unittest.TestCase):
    def test_synthetic_report_is_explicitly_marked(self):
        value, sha = load_json(ROOT / "examples/trivy-synthetic.json")
        report = import_report(value, sha)
        self.assertIn("SYNTHETIC", report["coverage"]["limitations"][0])
        self.assertEqual(report["findings"][0]["category"], "known-vulnerability")

    def test_malformed_scanner_output_is_rejected(self):
        with self.assertRaises(ValueError):
            import_report({"SchemaVersion": 2}, "sha")

    def test_container_has_no_network_pull_or_docker_socket(self):
        command = build_command(["docker", "--host", "unix:///var/run/docker.sock"], DIGEST,
                                Path("/tmp/image.tar"), Path("/tmp/cache"))
        self.assertIn("--network=none", command)
        self.assertIn("--pull=never", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        mounts = [command[i + 1] for i, x in enumerate(command) if x == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(all(x.endswith("readonly") for x in mounts))
        self.assertTrue(all("docker.sock" not in x for x in mounts))
        self.assertIn("--disable-telemetry", command[-1])
        self.assertIn("--skip-version-check", command[-1])

    def test_unpinned_scanner_is_rejected(self):
        with self.assertRaises(ValueError):
            build_command(["docker"], "trivy:latest", Path("/tmp/image.tar"), Path("/tmp/cache"))

    def test_remote_docker_engine_is_refused(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote.invalid:2376"}):
            with self.assertRaises(ValueError):
                local_engine()

    def test_offline_cache_timestamp_and_hash_are_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp)
            (cache / "db").mkdir()
            (cache / "db/trivy.db").write_bytes(b"synthetic-db-not-a-real-scanner-database")
            stamp = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
            (cache / "db/metadata.json").write_text(json.dumps({"UpdatedAt": stamp}))
            result = database_info(cache)
            self.assertGreater(result["age_days"], 19)
            self.assertEqual(len(result["db_sha256"]), 64)

    def test_scan_gate_and_existing_output_do_not_execute_container(self):
        with tempfile.TemporaryDirectory() as temp, patch("sys.stderr", new=io.StringIO()), \
             patch("offline_auditor.cli.scan_image") as scan:
            args = ["scan-image", "missing.tar", "--cache", "missing", "--scanner-image", DIGEST,
                    "--output", str(Path(temp) / "new")]
            self.assertEqual(main(args), 2)
            scan.assert_not_called()
            (Path(temp) / "new").mkdir()
            self.assertEqual(main(args + ["--allow-local-container"]), 2)
            scan.assert_not_called()

    def test_scan_failure_is_saved_as_error_not_clean(self):
        with tempfile.TemporaryDirectory() as temp, patch("sys.stderr", new=io.StringIO()):
            output = Path(temp) / "failed"
            result = main(["scan-image", "missing.tar", "--cache", "missing", "--scanner-image", DIGEST,
                           "--output", str(output), "--allow-local-container"])
            self.assertEqual(result, 2)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["assessment"], "SCAN_ERROR")
            self.assertEqual(report["coverage"]["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
