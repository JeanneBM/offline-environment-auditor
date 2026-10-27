"""Rules over local evidence. Findings are review items, not proof of exploitability."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

MAX_BYTES = 32 * 1024 * 1024
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
SUPPORTED = WORKLOADS | {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "Namespace", "NetworkPolicy"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    resource: str
    title: str
    evidence: str
    recommendation: str
    category: str = "configuration"
    owner: str = "unassigned"

    def to_dict(self):
        result = asdict(self)
        identity = json.dumps([self.rule_id, self.resource, self.evidence], ensure_ascii=False)
        result["id"] = hashlib.sha256(identity.encode()).hexdigest()[:16]
        return result


def load_json(path):
    path = Path(path)
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds 32 MiB")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def pointer(*parts):
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def identity(obj):
    meta = obj.get("metadata", {})
    return f"{obj['kind']}:{meta.get('namespace', '_cluster')}/{meta.get('name', '_unnamed')}"


def pod_spec(obj):
    if obj["kind"] == "Pod":
        return obj.get("spec", {}), ["spec"]
    if obj["kind"] == "CronJob":
        return obj.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}), ["spec", "jobTemplate", "spec", "template", "spec"]
    return obj.get("spec", {}).get("template", {}).get("spec", {}), ["spec", "template", "spec"]


def workload_findings(obj):
    spec, base = pod_spec(obj)
    resource = identity(obj)
    result = []
    def add(rule, severity, title, path, value, recommendation):
        # Deliberately do not serialize raw objects, env values, annotations or Secret data.
        result.append(Finding(rule, severity, resource, title,
                              pointer(*(base + path)) + " = " + json.dumps(value), recommendation))
    for setting in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(setting) is True:
            add("K8S-HOST-ACCESS", "HIGH", "Workload shares a host namespace", [setting], True,
                "Review the need for host namespace access and isolate the workload where feasible.")
    if any("hostPath" in v for v in spec.get("volumes", [])):
        add("K8S-HOST-PATH", "HIGH", "Workload declares a hostPath volume", ["volumes"], "hostPath present; path omitted",
            "Review host filesystem access, mount permissions and the necessity of this volume.")
    pod_context = spec.get("securityContext", {})
    for group in ("containers", "initContainers", "ephemeralContainers"):
        for i, container in enumerate(spec.get(group, [])):
            security = container.get("securityContext", {})
            path = [group, i]
            if security.get("privileged") is True:
                add("K8S-PRIVILEGED", "HIGH", "Container is privileged", path + ["securityContext", "privileged"], True,
                    "Remove privileged mode unless a reviewed, documented exception is required.")
            if security.get("allowPrivilegeEscalation") is not False:
                add("K8S-ESCALATION", "MEDIUM", "Privilege escalation is not explicitly disabled",
                    path + ["securityContext", "allowPrivilegeEscalation"], security.get("allowPrivilegeEscalation"),
                    "Set allowPrivilegeEscalation=false where compatible with the workload.")
            if security.get("runAsNonRoot", pod_context.get("runAsNonRoot")) is not True:
                add("K8S-NONROOT", "MEDIUM", "Non-root execution is not enforced",
                    path + ["securityContext", "runAsNonRoot"], "not enforced in container or Pod context",
                    "Verify the runtime user and enforce non-root execution where supported. Missing policy does not prove root execution.")
            caps = security.get("capabilities", {})
            if any(c in ("ALL", "SYS_ADMIN", "NET_ADMIN") for c in caps.get("add", [])):
                add("K8S-CAPABILITIES", "HIGH", "Container adds broad capabilities",
                    path + ["securityContext", "capabilities", "add"], caps["add"],
                    "Review added capabilities; prefer dropping ALL and adding only individually justified capabilities.")
            if security.get("readOnlyRootFilesystem") is not True:
                add("K8S-WRITABLE-ROOT", "LOW", "Read-only root filesystem is not enforced",
                    path + ["securityContext", "readOnlyRootFilesystem"], security.get("readOnlyRootFilesystem"),
                    "Consider a read-only root filesystem with explicit writable volumes.")
            image = container.get("image", "")
            if not isinstance(image, str) or not re.search(r"@sha256:[a-fA-F0-9]{64}$", image):
                add("K8S-IMAGE-PIN", "LOW", "Image is not pinned to a SHA-256 digest", path + ["image"],
                    "digest absent; image reference omitted", "Pin a reviewed image digest and update it through the delivery process.")
            limits = container.get("resources", {}).get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                add("K8S-LIMITS", "LOW", "CPU or memory limit is absent", path + ["resources", "limits"],
                    {"cpu_present": bool(limits.get("cpu")), "memory_present": bool(limits.get("memory"))},
                    "Review resource requests and limits against workload behavior and cluster policy.")
    return result


def rbac_findings(obj):
    resource = identity(obj)
    result = []
    if obj["kind"] in ("Role", "ClusterRole"):
        for i, rule in enumerate(obj.get("rules", [])):
            if any("*" in rule.get(k, []) for k in ("verbs", "resources", "apiGroups", "nonResourceURLs")):
                result.append(Finding("RBAC-WILDCARD", "HIGH", resource,
                    "Broad RBAC rule definition; effective bindings not evaluated", pointer("rules", i) + " contains wildcard",
                    "Replace wildcard grants where practical and review actual bindings and aggregation before assessing effective access."))
    if obj["kind"] in ("RoleBinding", "ClusterRoleBinding") and obj.get("roleRef", {}).get("name") == "cluster-admin":
        result.append(Finding("RBAC-ADMIN-BINDING", "HIGH", resource, "Binding references cluster-admin",
            pointer("roleRef", "name") + " = cluster-admin",
            "Review subjects, scope and operational necessity. A legitimate administrative binding is not proof of compromise."))
    return result


def audit_snapshot(document, source_hash):
    if not isinstance(document, dict):
        raise ValueError("Expected a Kubernetes List object")
    if document.get("kind") != "List" or not isinstance(document.get("items"), list):
        raise ValueError("Supply one Kubernetes kind=List JSON export")
    if len(document["items"]) > 50000:
        raise ValueError("Too many resources")
    findings, excluded, unsupported, counts = [], 0, set(), {}
    for obj in document["items"]:
        if not isinstance(obj, dict) or not isinstance(obj.get("kind"), str):
            raise ValueError("Invalid resource entry")
        kind = obj["kind"]
        if kind == "Secret":
            excluded += 1
            continue
        if kind not in SUPPORTED:
            unsupported.add(kind)
            continue
        if kind in WORKLOADS and pod_spec(obj)[0].get("os", {}).get("name") == "windows":
            unsupported.add("WindowsWorkload")
            continue
        counts[kind] = counts.get(kind, 0) + 1
        if kind in WORKLOADS:
            findings.extend(workload_findings(obj))
        else:
            findings.extend(rbac_findings(obj))
    unique = {x.to_dict()["id"]: x.to_dict() for x in findings}
    return {"schema": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "assessment": "REVIEW_REQUIRED" if unique else "NO_FINDINGS_IN_CHECKED_SCOPE",
            "coverage": {"status": "PARTIAL", "ruleset_version": "0.1.0", "source_sha256": source_hash, "objects_checked": counts,
                         "secret_objects_excluded": excluded, "unsupported_kinds": sorted(unsupported),
                         "limitations": ["Local snapshot only; capture time and inventory completeness are not verified.",
                                         "Absence of a finding is not proof of security.",
                                         "Runtime exploitability, effective RBAC, CNI enforcement, host configuration and image CVEs were not checked."]},
            "findings": sorted(unique.values(), key=lambda x: (x["resource"], x["rule_id"], x["evidence"]))}
