# Security Policy

## Overview

K8sAttackMap is a security-focused open-source tool. We take the security of this project seriously. If you discover a vulnerability in K8sAttackMap itself, we appreciate your responsible disclosure and will work with you to resolve it promptly.

---

## Supported Versions

Only the latest release of K8sAttackMap receives security fixes. We encourage all users to keep their installation up to date.

| Version        | Supported |
|----------------|-----------|
| Latest release | ✅ Yes     |
| Older releases | ❌ No      |

---

## Reporting a Vulnerability

> [!WARNING]
> **Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability, please use one of the following private channels:

- **GitHub Private Security Advisory** *(preferred)*: [Open a private advisory](https://github.com/SaptarshiSarkar12/K8sAttackMap/security/advisories/new)
- **Email**: Contact the maintainer directly via email listed on the [GitHub profile](https://github.com/SaptarshiSarkar12)

### What to include in your report

Please provide as much of the following as possible to help us triage and reproduce the issue:

- A clear description of the vulnerability and its potential impact
- The component(s) affected (e.g., `K8sJsonParser`, `TrivyScanner`, CLI argument parsing, export functions)
- Steps to reproduce the issue or a proof-of-concept
- The K8sAttackMap version you are using and your operating system
- Any relevant logs or output (redact any sensitive cluster data)

If we need more information from you, we will reach out via the channel you used to report.

---

## Severity Classification

We classify vulnerabilities based on their potential impact and ease of exploitation:

| Severity | Description                                                                                                                                      |
|----------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Critical | Remote code execution, complete data exposure, or any vulnerability that can be easily exploited with minimal user interaction.                  |
| High     | Significant data exposure, privilege escalation, or vulnerabilities that require some user interaction but are still relatively easy to exploit. |
| Medium   | Vulnerabilities that could lead to data exposure or security issues but require more complex exploitation or specific conditions.                |
| Low      | Issues that have limited impact, require significant user interaction, or are unlikely to be exploited in practice.                              |

---

## Scope

### In scope

The following are considered in scope for vulnerability reports:

- **Cluster data handling**: Vulnerabilities in how `K8sJsonParser` or `KubectlExtractor` parses or stores Kubernetes JSON/YAML that could lead to data exposure or code execution
- **CLI argument injection**: Issues where malformed CLI flags could lead to unexpected command execution or path traversal (e.g., in `CommandParser`, `WorkspaceManager`)
- **Trivy integration**: Vulnerabilities in how scan results are ingested or cached that could lead to misleading security output or injection (`TrivyScanner`, `TrivyJsonParser`, `TrivyCache`)
- **Export functions**: Path traversal or file overwrite issues in `CytoscapeExporter`, `PdfReportEngine`, or `ExportService`
- **Dependency vulnerabilities**: High/critical CVEs in transitive or direct Maven dependencies (please check if a fix is already planned before reporting)
- **Logic flaws in analysis**: Flaws that could cause the tool to systematically under-report or suppress real attack paths

### Out of scope

The following are **not** in scope:

- Vulnerabilities in Kubernetes clusters that K8sAttackMap is used to *analyse* — those should be reported to the respective Kubernetes project or vendor
- CVEs in Trivy itself — report those to the [Trivy project](https://github.com/aquasecurity/trivy/security)
- Issues requiring physical access to the machine running K8sAttackMap
- Denial-of-service attacks via extremely large cluster snapshots (known limitation; mitigation contributions are welcome)
- Social engineering of maintainers

---

## Security Design Considerations

K8sAttackMap operates with the following security properties by design:

- **Read-only cluster access**: When using `kubectl` to extract cluster data, K8sAttackMap only performs read operations and does not attempt to modify any cluster resources.
- **Local execution**: All analysis runs locally. No cluster data, graph data, or scan results are transmitted to any external service.
- **No persistent credentials**: K8sAttackMap does not store kubeconfig credentials or cluster tokens; it delegates to `kubectl` and inherits the caller's existing RBAC context.
- **Offline mode supported**: The tool can analyse a pre-exported cluster JSON snapshot without any network connectivity, limiting the attack surface of the tool itself. Only `Trivy` scanning may require network access to fetch vulnerability databases on first run (this is cached; you can also supply a pre-downloaded Trivy DB for fully offline scans). K8sAttackMap does not yet support offline scanning of container images, but this is planned for a future release.

Users are responsible for securing the environment in which K8sAttackMap is executed and for appropriately protecting exported reports (`k8s-threat-map.html`, `k8s-threat-report.pdf`), as these may contain sensitive information about your cluster's security posture.

---

## Coordinated Disclosure Policy

We follow a **coordinated (responsible) disclosure** model:

1. Reporter submits vulnerability privately.
2. Maintainer acknowledges, investigates, and develops a fix.
3. A fix is prepared and a release is scheduled.
4. The reporter is notified ahead of the public release.
5. The fix is released publicly; a GitHub Security Advisory is published.

We ask reporters to **refrain from public disclosure for a minimum of 90 days** from the date of initial report, or until a fix is publicly available — whichever comes first. We will aim to meet this window.

Credit will be given to reporters in the release notes and GitHub Security Advisory unless anonymity is requested.

---

## Acknowledgements

We are grateful to the security researchers and community members who help keep K8sAttackMap and its users safe. Responsible disclosures will be credited in our release notes.

---

## Additional Resources

- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Contributing Guidelines](./CONTRIBUTING.md)
- [Apache 2.0 License](./LICENSE)
- [GitHub Security Advisories for this repository](https://github.com/SaptarshiSarkar12/K8sAttackMap/security/advisories)