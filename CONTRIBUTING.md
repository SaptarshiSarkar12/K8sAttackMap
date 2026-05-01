# Contributing to K8sAttackMap

Thank you for your interest in contributing to **K8sAttackMap**! Whether you're fixing a bug, adding a feature, improving documentation, or reporting an issue, your help is genuinely appreciated. This guide covers everything you need to get up and running as a contributor.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Fork & Clone](#fork--clone)
    - [Build from Source](#build-from-source)
    - [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
    - [Branching Strategy](#branching-strategy)
    - [Making Changes](#making-changes)
    - [Running Tests](#running-tests)
    - [Native Image Builds](#native-image-builds)
- [Code Style Guidelines](#code-style-guidelines)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)
- [License](#license)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold a welcoming and respectful environment for everyone. Please read it before engaging with the community.

---

## Ways to Contribute

You don't have to write code to contribute. Here are the main ways to help:

- **Bug reports** — Found something broken? Open an issue with a clear reproduction case.
- **Feature requests** — Have an idea to improve attack path analysis, add a new edge type, or enhance output formats? Share it!
- **Code contributions** — Fix bugs, implement features, or improve test coverage.
- **Documentation** — Improve the README, add inline code comments, or expand this guide.
- **Testing on real clusters** — Run K8sAttackMap against your own cluster snapshots and report unexpected results or edge cases.

---

## Getting Started

### Prerequisites

Make sure you have the following installed before you begin:

| Tool                                                                 | Version     | Purpose                            |
|----------------------------------------------------------------------|-------------|------------------------------------|
| [GraalVM](https://www.graalvm.org/downloads/)                        | 25 (JDK 25) | Compile and build native images    |
| [Maven](https://maven.apache.org/)                                   | 3.9+        | Build system                       |
| [Trivy](https://trivy.dev/docs/latest/getting-started/installation/) | ≥ 0.70.0    | CVE scanning (required at runtime) |
| `kubectl`                                                            | any         | Live cluster extraction (optional) |
| Git                                                                  | any         | Version control                    |

### Fork & Clone

1. [Fork the repository](https://github.com/SaptarshiSarkar12/K8sAttackMap/fork) to your GitHub account.
2. Clone your fork locally:

   ```bash
   git clone https://github.com/<your-username>/K8sAttackMap.git
   cd K8sAttackMap
   ```

3. Add the upstream remote so you can keep your fork in sync:

   ```bash
   git remote add upstream https://github.com/SaptarshiSarkar12/K8sAttackMap.git
   ```

### Build from Source

Set up your GraalVM environment and build the native binary:

```bash
# Point to your local GraalVM installation
export GRAALVM_HOME=/path/to/graalvm
export PATH=$GRAALVM_HOME/bin:$PATH
export LD_LIBRARY_PATH=$GRAALVM_HOME/lib:$LD_LIBRARY_PATH

# Build the native binary (output: target/K8sAttackMap)
mvn clean package
```

To run the tool against a saved cluster snapshot after building:

```bash
./target/K8sAttackMap -k cluster-state.json
```

To regenerate GraalVM Native Image metadata (needed when reflection/serialization usage changes):

```bash
mvn -P generate-graalvm-metadata exec:exec@java-agent
```
This will run the tool with the GraalVM agent, which observes runtime behavior and generates metadata files under `src/main/resources/META-INF/native-image/`.
Commit any updated metadata files if your change affects reflection or dynamic class loading.
You may need to add arguments (`-k` and `/path/to/cluster-state.json`) to the agent run configuration if you want the tool to use a saved cluster snapshot during metadata generation.

### Project Structure

Understanding the layout will help you find the right file for your change:

```
src/main/java/io/github/SaptarshiSarkar12/k8sattackmap/
│
├── K8sAttackMapApplication.java   # Entry point and top-level wiring
│
├── cli/                           # Argument parsing (Apache Commons CLI)
├── ingestion/                     # Cluster data parsing and kubectl extraction
├── model/                         # Core domain types (GraphNode, GraphEdge, EdgeType, …)
├── security/                      # Trivy scanning, edge risk scoring, attack surface classification
├── analysis/                      # Core algorithms: path discovery, choke points, blast radius, loop detection
│   ├── graph/                     # Dijkstra, AllDirectedPaths, PrivilegeLoopDetector
│   ├── chokepoint/                # ChokePointIdentifier, ChokePointRemediationAdvisor
│   ├── blast/                     # BlastRadiusAnalyzer (BFS)
│   └── remediation/               # Remediation plan generation
├── export/                        # Output generation: console, HTML (Cytoscape.js), PDF (iText)
└── util/                          # Shared utilities, constants, logging helpers
```

Key dependency highlights:
- **JGraphT** — directed weighted multigraph, Dijkstra, Johnson's cycle algorithm
- **Jackson** — Kubernetes JSON parsing
- **iText html2pdf** — PDF report generation
- **Logback/SLF4J** — structured logging
- **Lombok** — boilerplate reduction
- **JUnit Jupiter** — unit testing

---

## Development Workflow

### Branching Strategy

All work happens off `main`. Create a dedicated branch for each contribution:

```bash
# Sync your fork with upstream first
git fetch upstream
git checkout main
git merge upstream/main

# Create a focused branch
git checkout -b fix/privilege-loop-false-positive
# or
git checkout -b feat/add-ingress-edge-type
# or
git checkout -b docs/improve-cli-reference
```

Branch naming conventions:

| Prefix      | Use for                                     |
|-------------|---------------------------------------------|
| `feat/`     | New features or enhancements                |
| `fix/`      | Bug fixes                                   |
| `docs/`     | Documentation-only changes                  |
| `refactor/` | Code restructuring without behavior changes |
| `test/`     | Adding or improving tests                   |
| `chore/`    | Build scripts, dependency updates, tooling  |

### Making Changes

A few pointers before you start coding:

- **One concern per PR.** Keep pull requests focused — a fix and an unrelated refactor belong in separate PRs.
- **Understand the graph model first.** Changes to `GraphNode`, `GraphEdge`, or `EdgeType` ripple across parsing, analysis, and export. Read those classes before touching them.
- **Edge weights matter.** If you add a new edge type or change how `EdgeRiskScorer` computes weights, document the rationale. The Dijkstra path-of-least-resistance result changes with every weight adjustment.
- **GraalVM reflection.** If you add new classes that are accessed via reflection, serialization, or dynamic proxy at runtime, regenerate the GraalVM metadata (see [Native Image Builds](#native-image-builds)) and commit the updated files under `src/main/resources/META-INF/native-image/`.
- **Test with a real snapshot.** Before submitting, run your change against an actual cluster JSON. The `ingestion/` layer handles many edge cases in the Kubernetes API output that are hard to catch with unit tests alone.

### Running Tests

```bash
mvn test
```

Tests use JUnit Jupiter 6. Test classes live under `src/test/` mirroring the main package structure.

When adding new functionality, please add matching tests. For analysis algorithms (path discovery, blast radius, choke points), construct a small synthetic graph in the test to validate the algorithm logic independently of the parser.

### Native Image Builds

The project ships platform-specific native binaries via GraalVM. Three Maven profiles target different platforms:

```bash
mvn clean package -P build-ubuntu-latest  # → target/linux/K8sAttackMap
mvn clean package -P build-windows-latest # → target/windows/K8sAttackMap.exe
mvn clean package -P build-macos-latest   # → target/macos/K8sAttackMap
```
Native images are automatically built by GitHub Actions CI/CD workflow. 

---

## Code Style Guidelines

The project follows standard Java conventions. Please keep these in mind:

**General**
- Use Lombok annotations (`@Getter`, `@Slf4j`, `@Builder`, etc.) to reduce boilerplate, consistent with the rest of the codebase.
- Use `var` where the inferred type is obvious from the right-hand side (Java 25 feature in use).
- Prefer descriptive names to abbreviations. `attackPathDiscovery` is better than `apd`.
- Avoid raw types; always parameterize generics.

**Logging**
- Use SLF4J (`log.info`, `log.debug`, `log.warn`, `log.error`). Never use `System.out.println` for diagnostic output — use `AnalysisSummaryPrinter` for intentional console output.
- `--verbose` mode maps to `DEBUG` level. Put detailed internal state there, not at `INFO`.

**Edge types and graph integrity**
- New `EdgeType` values must be added to the enum in `EdgeType.java` and documented with a comment explaining what relationship they represent.
- Every new edge type must be handled in `EdgeRiskScorer` (weight contribution) and `AnalysisSummaryPrinter` (display label). Missing handling will cause silent failures.

**Output formats**
- HTML output is generated via `CytoscapeExporter`. Node and edge styling changes belong there.
- PDF output is generated via `PdfReportEngine` using iText html2pdf.

The html templates in `src/main/resources/templates/` are used for the PDF report and for html export. Modifying the structure or styling of the report should be done by editing these templates, not by hardcoding HTML in Java.

**Formatting**
- Use 4-space indentation (no tabs).
- Organise imports: standard library → third-party → internal. Remove unused imports before committing.

---

## Submitting a Pull Request

1. **Ensure your branch is up to date** with `upstream/main` before opening a PR.

   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Commit message format.** Use a short imperative subject line, optionally followed by a blank line and a longer body:

   ```
   Add node_escape edge type for privileged container breakout

   Containers running with hostPID=true or securityContext.privileged=true
   now get a node_escape edge to the host Node resource. EdgeRiskScorer
   assigns weight 0.1 (very easy traversal) to these edges.

   Fixes #42
   ```

3. **Push your branch** to your fork:

   ```bash
   git push origin feat/add-node-escape-edge
   ```

4. **Open a Pull Request** against `main` in the upstream repository. In the PR description:
    - Explain *what* changed and *why*.
    - Reference any related issues with `Fixes #<number>` or `Closes #<number>`.
    - Include before/after console output or screenshots for user-facing changes.
    - Note if the change requires regenerated GraalVM metadata.

5. **Respond to review feedback.** Address comments with new commits or by revising your branch. Avoid force-pushing once a review is in progress unless asked.

6. **Squash or clean up commits** before the PR is merged if requested. A clean, logical commit history is preferred over a long chain of "fix typo" commits.

---

## Reporting Issues

Before opening a new issue, please [search existing issues](https://github.com/SaptarshiSarkar12/K8sAttackMap/issues) to avoid duplicates.

When filing a bug report, include:

- The K8sAttackMap version or commit SHA you're using.
- Your operating system and architecture.
- The exact command you ran.
- The full console output (use `--verbose` to capture debug logs).
- If the issue relates to parsing, a **minimal anonymised cluster JSON** that reproduces the problem. Remove real resource names and sensitive values — the structure is what matters.

For feature requests, describe the use case you're trying to support and, if possible, the kind of output or behavior you'd expect.

---

## Security Vulnerabilities

**Please do not report security vulnerabilities via public GitHub issues.**

K8sAttackMap itself analyses cluster security — it would be ironic to have a vulnerable tool. If you discover a vulnerability in K8sAttackMap (not in an analysed cluster), contact the maintainer privately before disclosing publicly. Check the [SECURITY.md](SECURITY.md) file for details on how to report securely.

---

## License

By contributing to K8sAttackMap, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE), the same license that covers the rest of the project.