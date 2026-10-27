# Initial ruleset 0.1.0

| Rule | Default severity | Evidence and limitation |
| --- | --- | --- |
| K8S-PRIVILEGED | HIGH | privileged=true; legitimate infrastructure agents may require an exception |
| K8S-HOST-ACCESS | HIGH | hostNetwork, hostPID or hostIPC enabled; not a proof of host compromise |
| K8S-HOST-PATH | HIGH | hostPath declared; path omitted from report; actual mounts/access require review |
| K8S-ESCALATION | MEDIUM | allowPrivilegeEscalation is not explicitly false |
| K8S-NONROOT | MEDIUM | runAsNonRoot not enforced at container or Pod level; missing policy is not proof of root execution |
| K8S-CAPABILITIES | HIGH | ALL, SYS_ADMIN or NET_ADMIN explicitly added |
| K8S-WRITABLE-ROOT | LOW | readOnlyRootFilesystem is not explicitly true |
| K8S-IMAGE-PIN | LOW | No explicit SHA-256 image digest; digest pinning alone does not establish image trust |
| K8S-LIMITS | LOW | CPU or memory limit missing; performance and availability tradeoffs require workload-specific judgment |
| RBAC-WILDCARD | HIGH | Wildcard grant definition; bindings and aggregated roles are not resolved |
| RBAC-ADMIN-BINDING | HIGH | RoleBinding or ClusterRoleBinding references cluster-admin; scope and subjects need manual review |
| TRIVY-advisory-ID | Scanner severity | Package/version match imported from scanner output, not independently confirmed exploitability |

These rules intentionally produce review items rather than compliance verdicts. They do not implement an entire Kubernetes benchmark. NetworkPolicy objects may appear in inventory but CNI enforcement, reachability and policy semantics are not assessed. Unknown resource kinds are listed as unsupported.

Findings have stable IDs based on rule, resource and evidence. Exact repeated findings are deduplicated. A Deployment and its resulting Pod remain distinct observed resources, so cross-resource remediation grouping is not implemented.
