# Offline Environment Auditor

**Local evidence in. Reviewable findings and coverage limits out. No cloud model or online lookup.**

A preliminary deterministic audit workflow for Linux Kubernetes configuration snapshots and local Trivy vulnerability reports. An optional Docker adapter scans image archives in a container with networking disabled and preloaded vulnerability databases.

This is an auditor, not an autonomous remediation agent. It does not execute fixes, exploit services or certify an environment as secure.

## Run immediately

Python 3.11 or newer; no installation or third-party Python package is needed:

```bash
python run_audit.py audit-k8s examples/k8s-snapshot.json --output .local/demo-001
```

Open .local/demo-001/report.html locally. The companion report.json contains machine-readable findings. Use a new output directory for each run; existing reports are never overwritten.

```bash
python -m unittest discover -s tests -v
```

Optional package installation is available through pyproject.toml. On an air-gapped host, use the no-install launcher or a separately prepared, approved installation bundle; pip may otherwise fetch build tooling.

## Implemented scope

| Path | What it checks | What it does not establish |
| --- | --- | --- |
| audit-k8s | Privileged containers, host namespaces, hostPath, privilege escalation, non-root policy, capabilities, writable root filesystem, image digest pinning, limits and broad RBAC definitions/bindings | Effective permissions, exploitability, runtime isolation, full cluster inventory or compliance |
| import-trivy | Normalizes known package vulnerability findings from an existing schema-2 Trivy JSON report | Authenticity, database age or successful execution of an arbitrary imported scan |
| scan-image | Runs an already-loaded digest-pinned scanner against a local image archive and imported database cache, with Docker network=none and pull=never | Complete CVE coverage, zero-days, database authenticity or runtime exploitability |

Supported workload shapes include Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs and CronJobs, including init and ephemeral containers. Windows workloads are explicitly outside the current ruleset. Role findings describe definitions; the tool does not calculate effective RBAC grants.

Secret objects are skipped. Environment values, annotations, raw object snapshots and host filesystem paths are not copied into reports. Resource names remain visible and can be sensitive. Keep reports local and review them before sharing.

## Report contract

Each finding contains a stable ID, rule ID, severity, resource, evidence pointer, recommendation, category and an unassigned owner. Configuration review items and scanner-reported known vulnerabilities are distinct categories.

Every report includes coverage limitations and an input hash. Coverage is deliberately PARTIAL for this preliminary implementation. No findings means no findings in the checked scope, not a clean bill of health. Failed scanner execution produces SCAN_ERROR and ERROR coverage, never a clean result.

## Optional Trivy import

```bash
python run_audit.py import-trivy examples/trivy-synthetic.json --output .local/import-demo-001
```

The supplied Trivy input is explicitly synthetic and uses DEMO-NOT-A-CVE. It is a parser fixture, not evidence of a real vulnerability scan.

For a real import, supply your existing local Trivy JSON file instead. No external advisory links or online severity lookups are followed.

## Isolated image scanning

Provide an approved scanner image already loaded in the local Docker engine, a local image archive and a readable imported cache. See docs/offline-operation.md before running:

```bash
python run_audit.py scan-image .local/image.tar --cache .local/trivy-cache --scanner-image YOUR_APPROVED_IMAGE_AT_SHA256_DIGEST --output .local/image-scan-001 --allow-local-container
```

Replace the image placeholder with an actual approved image reference containing @sha256 and its 64-character digest. No digest is invented in this repository. Missing images, incompatible scanner flags or unavailable databases fail closed. The adapter never downloads its prerequisites.

## Exit codes

- 0: audit completed; not a security approval.
- 1: the optional --fail-on HIGH or --fail-on CRITICAL finding gate was exceeded.
- 2: input, setup or execution error.

## Structure

| Location | Purpose |
| --- | --- |
| src/offline_auditor | Rules, scanner adapter, reports and CLI |
| run_audit.py | No-install launcher |
| examples | Synthetic configuration and parser examples |
| tests | Offline rules, confidentiality, reporting and isolation-contract tests |
| docs/offline-operation.md | Offline prerequisites and network boundary |
| docs/rules.md | Meaning and limitations of rules |
| docs/status.md | Verification and remaining work |
| .github/workflows/ci.yml | Python 3.11–3.13 checks without model or scanner requests |

## Next steps

Validate the container adapter with an approved Trivy version and real local archives, record representative internal snapshots and review false positives. Broader host/IaC collectors, risk enrichment, owner mapping and optional local-model explanations are future work. No LLM is required for the implemented checks.
