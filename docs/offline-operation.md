# Offline operation and trust boundary

## Offline means a defined boundary

audit-k8s and import-trivy read explicitly supplied local JSON files and write local reports. They do not invoke kubectl, a model, a browser, HTTP clients or update services. They do not discover hosts or collect live cloud inventory.

The host operating system, Python installation, storage, Docker daemon and browser remain outside this application's security boundary. Host telemetry, remote desktop and unrelated processes require separate organizational egress controls. The repository does not claim to disable the machine's network interfaces.

## Kubernetes inputs

Prepare an authorized Kubernetes List JSON export separately. Do not include Secret resources. Workload objects can still contain plaintext environment values, annotations and internal addresses; protect the raw snapshot even though reports omit those fields.

For a namespace-level inventory, export only the approved workload and RBAC object types from the intended internal cluster using your normal administrative process. Store snapshots under .local, not in public Git history. ClusterRoles and ClusterRoleBindings require a separately approved cluster-wide scope. An omitted kind is unknown, not absent.

This version does not prove capture time, inventory completeness, effective user permissions or the identity of the source cluster. Do not describe its report as a complete assessment of a cloud account, host or network.

## Image scanner prerequisites

Prepare the following outside the scanning session through an approved update/import process:

1. A compatible Trivy container image with an approved SHA-256 reference, loaded into the local engine.
2. A local Docker/OCI-compatible image archive supported by that scanner version.
3. A Trivy cache containing db/trivy.db and db/metadata.json; include java-db assets if needed by the input.
4. Verified provenance for the scanner and database bundle. A local hash detects changes but is not a signature or authenticity check.

No updater, registry login, image pull or external database fetch is implemented. Do not put registry credentials, unrelated private files or plugins into the mounted database cache.

The cache and archive must be readable by container UID 65532. The cache is mounted read-only and copied to a temporary in-container location. Paths containing commas or newlines are refused rather than ambiguously interpreted by Docker's mount syntax.

## Container isolation contract

The adapter rejects remote TCP/SSH Docker engines. It resolves a local Unix socket or Windows named pipe and passes that endpoint explicitly to Docker.

The scanner runs with:

- --network=none and --pull=never;
- read-only root filesystem, dropped capabilities and no-new-privileges;
- no mounted Docker socket, kubeconfig, credential directory or host root;
- exactly two read-only input mounts: the archive and database cache;
- a temporary cache, PID/CPU/memory limits and a process timeout;
- disabled database/check updates, offline dependency resolution, version checks and telemetry.

The trusted scanner container must provide /bin/sh and the trivy executable and support the configured flags. Pinning an arbitrary digest does not establish trust. Incompatible versions fail without a network fallback. Scanner stdout is spooled to a private temporary file and at most 32 MiB is parsed. The timeout and container limits are not a guarantee against every host resource-exhaustion condition.

No image archive content is executed as an application. Scanning still parses untrusted content, so scanner updates and isolation remain important.

## Database freshness

Database UpdatedAt, age and hashes are recorded for adapter-driven scans. A database older than seven days adds a warning; the threshold is informational, not a claim that newer data is sufficient. Newly disclosed vulnerabilities, unsupported packages and unavailable Java metadata can remain undetected.

Arbitrary imported Trivy reports do not establish database freshness. Their provenance and completeness must be verified separately. No live EPSS, KEV or exploit-availability enrichment is performed.

## Reports

HTML is self-contained, escapes input values, contains no scripts or external assets and carries a restrictive Content Security Policy. JSON evidence references allow manual inspection against the protected source. Never publish raw snapshots or reports without reviewing resource names and other identifying information.

Configuration severities are default review priorities, not CVSS scores or proof of exploitability. Every owner starts unassigned. No finding is automatically fixed, suppressed or risk-accepted.
