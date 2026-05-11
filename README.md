<div align="center">
  <a href="#quick-start">
    <img src="K8sAttackMap Banner.png" alt="K8sAttackMap" width="1200"/>
  </a>

  <br/>

[![CI: Build, Test & Package (GitHub Actions)](https://github.com/SaptarshiSarkar12/K8sAttackMap/actions/workflows/build.yml/badge.svg)](https://github.com/SaptarshiSarkar12/K8sAttackMap/actions/workflows/build.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java](https://img.shields.io/badge/Java-25-orange.svg)](https://openjdk.org/)
[![GraalVM](https://img.shields.io/badge/GraalVM-Native_Image-red.svg)](https://www.graalvm.org/)
[![Trivy](https://img.shields.io/badge/Scanner-Trivy-1904DA.svg)](https://trivy.dev/)
[![GitHub Issues](https://img.shields.io/github/issues/SaptarshiSarkar12/K8sAttackMap)](https://github.com/SaptarshiSarkar12/K8sAttackMap/issues)

**Kubernetes attack surface visualiser and security advisor.**  
Ingests a live or offline cluster snapshot, builds a directed attack graph across RBAC, workloads, secrets, and node
relationships, then surfaces the most dangerous paths, choke points, and remediation steps — all in a single command.

</div>

---

## Table of Contents

- [Why K8sAttackMap?](#why-k8sattackmap)
- [How It Works](#how-it-works)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
    - [Native Binary (recommended)](#native-binary-recommended)
    - [Build from Source](#build-from-source)
- [Quick Start](#quick-start)
- [Usage](#usage)
    - [CLI Reference](#cli-reference)
    - [Examples](#examples)
- [Output Formats](#output-formats)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

> [!NOTE]
> For detailed module breakdown and test organization, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Why K8sAttackMap?

Most Kubernetes security tools check policy compliance in isolation — they tell you a pod is privileged or a role has
wildcard verbs, but they don't tell you *what an attacker can actually reach* from that misconfiguration. K8sAttackMap
connects those dots.

Given a cluster snapshot, the tool:

1. Parses every workload, RBAC binding, secret, and service account relationship.
2. Scans container images for known CVEs using [Trivy](https://trivy.dev/).
3. Builds a weighted directed multigraph where edges represent real attack capabilities (`uses_sa`, `bound_to`,
   `can_access`, `mounts_secret`, `node_escape`, and more).
4. Runs `Dijkstra` and `AllDirectedPaths` to find the shortest and all possible compromise routes.
5. Identifies choke points — the single nodes whose hardening eliminates the most attack paths.
6. Detects privilege escalation loops (circular RBAC chains).
7. Outputs prioritised, actionable `kubectl` remediation commands.

---

## How It Works

```mermaid
flowchart TD
    %% Modern GitHub-inspired Dark Theme
    classDef inputNode fill:#238636,stroke:#2ea043,stroke-width:2px,color:#ffffff,font-family:sans-serif,rx:5px,ry:5px;
    classDef processNode fill:#1f6feb,stroke:#388bfd,stroke-width:2px,color:#ffffff,font-family:sans-serif,rx:5px,ry:5px;
    classDef dataNode fill:#8957e5,stroke:#a371f7,stroke-width:2px,color:#ffffff,font-family:sans-serif,rx:5px,ry:5px;
    classDef taskNode fill:#21262d,stroke:#30363d,stroke-width:2px,color:#c9d1d9,font-family:sans-serif,rx:5px,ry:5px;
    classDef outputNode fill:#da3633,stroke:#f85149,stroke-width:2px,color:#ffffff,font-family:sans-serif,rx:5px,ry:5px;
    classDef noteNode fill:none,stroke:none,color:#8b949e,font-family:sans-serif,font-style:italic,font-size:12px;
    classDef subgraphStyle fill:#0d1117,stroke:#30363d,stroke-width:1px,stroke-dasharray: 5 5,color:#c9d1d9,font-weight:bold;

    %% 1. Input Layer
    subgraph Stage1 ["1. Data Ingestion"]
        direction TB
        IN[("Cluster State\n(JSON / kubectl)")]:::inputNode
    end

    %% 2. Parsing & Scanning Layer
    subgraph Stage2 ["2. Parsing & Scanning"]
        direction TB
        P_Parser["K8sJsonParser"]:::processNode
        P_Scanner["TrivyScanner"]:::processNode
        P_Desc["Extracts Nodes → Edges\n& Security Facts (CVEs)"]:::noteNode
        
        P_Parser -.-> P_Desc
        P_Scanner -.-> P_Desc
    end

    %% 3. Core Data Model
    subgraph Stage3 ["3. Core Data Model"]
        direction TB
        CG[("Cluster Graph")]:::dataNode
        CG_Desc["DirectedWeightedMultigraph\n<GraphNode, GraphEdge>"]:::noteNode
        
        CG -.-> CG_Desc
    end

    %% 4. Orchestration & Analysis Layer
    subgraph Stage4 ["4. Analysis Orchestrator"]
        direction TB
        T1["Attack Path Discovery\n(Dijkstra + AllDirectedPaths)"]:::taskNode
        T2["Choke Point Identifier\n(Top impacted nodes)"]:::taskNode
        T3["Blast Radius Analyzer\n(BFS per entry point)"]:::taskNode
        T4["Privilege Loop Detector\n(Johnson's cycles)"]:::taskNode
        T5["Remediation Advisor\n(Actionable Fixes)"]:::taskNode
    end

    %% 5. Output Layer
    subgraph Stage5 ["5. Reporting & Exports"]
        direction TB
        OUT1["Console Summary\n(AnalysisSummaryPrinter)"]:::outputNode
        OUT2["Cytoscape Map\n(k8s-threat-map.html)"]:::outputNode
        OUT3["PDF Threat Report\n(k8s-threat-report.pdf)"]:::outputNode
    end

    %% Data Flow Routing
    IN ==>|Raw K8s Data| P_Parser
    IN ==>|Image Data| P_Scanner
    
    P_Parser ==>|Parsed Resources| CG
    P_Scanner ==>|Vulnerability Scores| CG
    
    CG ===>|Graph Traversal & Metrics| Stage4
    
    Stage4 ==>|Analysis Results| Stage5

    %% Apply Subgraph Styling
    class Stage1,Stage2,Stage3,Stage4,Stage5 subgraphStyle;

    %% Legend (Compact & integrated)
    subgraph Legend ["Legend"]
        direction TB
        L1(["Input"]):::inputNode
        L2(["Process"]):::processNode
        L3(["Data Structure"]):::dataNode
        L4(["Analysis Task"]):::taskNode
        L5(["Output Artifact"]):::outputNode
    end
    class Legend subgraphStyle;
```

Edge weights are computed by `EdgeRiskScorer` from per-node CVE scores, security context flags, and RBAC sensitivity. A
lower weight means an easier traversal for an attacker — Dijkstra finds the path of least resistance.

---

## Key Features

| Feature                         | Details                                                                                                                   |
|---------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| **Attack path discovery**       | Shortest paths (Dijkstra) and all simple paths up to depth `max(baseLen + 2, 8, 10)` per source→target pair               |
| **Choke point ranking**         | Nodes ranked by number of paths severed if hardened; top-5 displayed with weighted scores                                 |
| **Blast radius analysis**       | BFS from each compromised entry point up to configurable hop depth                                                        |
| **Privilege escalation loops**  | Johnson's simple cycle algorithm on a simplified graph; RBAC-only filter removes infrastructure ownership false positives |
| **CVE-aware scoring**           | Trivy scan results integrated into edge weights and node risk scores; results cached across runs                          |
| **Mounted secret detection**    | Edges created for `spec.volumes[].secret`, `envFrom.secretRef`, and `env[].valueFrom.secretKeyRef`                        |
| **Workload ownership chains**   | `Deployment → ReplicaSet → Pod` via `ownerReferences`; `Managed` edges modelled                                           |
| **Group expansion**             | `system:serviceaccounts` and `system:serviceaccounts:<ns>` groups expanded to individual SA nodes                         |
| **ClusterRole cross-namespace** | ClusterRole `can_access` edges correctly cover all namespaces, not just `cluster-scoped`                                  |
| **Native binary**               | Built with GraalVM Native Image; no JVM required at runtime                                                               |
| **HTML visualisation**          | Interactive Cytoscape.js graph with blast radius highlighting, entry/choke point colouring                                |
| **PDF report**                  | Structured audit report with executive summary, choke point table, attack path hops, remediation cards, CVE summary       |

---

## Prerequisites

| Tool                                                                 | Version  | Purpose                                                                 |
|----------------------------------------------------------------------|----------|-------------------------------------------------------------------------|
| [Trivy](https://trivy.dev/docs/latest/getting-started/installation/) | ≥ 0.70.0 | Container image CVE scanning                                            |
| `kubectl`                                                            | any      | Live cluster extraction (optional — JSON file can be provided directly) |

To capture a live cluster snapshot:

```bash
kubectl get pods,services,serviceaccounts,roles,clusterroles,rolebindings,clusterrolebindings,secrets,configmaps,deployments,replicasets,daemonsets,statefulsets,nodes -A -o json > cluster-state.json
```

> [!IMPORTANT]
> Trivy must be on your `PATH`.  
> K8sAttackMap calls `trivy image --format json` for each unique container image it encounters.

---

## Installation

### Native Binary (recommended)

Download the latest pre-built binary for your platform from the [Releases](https://github.com/SaptarshiSarkar12/K8sAttackMap/releases) page.

> [!TIP]
> For easier global access, move the downloaded binary to a directory included in your system's `PATH` (e.g., `/usr/local/bin` on Linux/macOS).

```bash
# Linux / macOS
chmod +x k8sattackmap
./k8sattackmap --help

# Windows
k8sattackmap.exe --help
```

### Build from Source

See [CONTRIBUTING.md - Build from Source](CONTRIBUTING.md#build-from-source) for detailed setup including GraalVM configuration and native image compilation.

---

## Quick Start

Run the tool against a live cluster or a saved JSON snapshot. By default, it auto-discovers entry points and targets,
finds the most dangerous path, identifies choke points, and prints a console summary.

> [!WARNING]
> **Prerequisites:** Ensure `trivy` is on your `PATH` and you have `kubectl` access (for live cluster mode) or a saved cluster snapshot before running these commands.

### Run against live cluster

```bash
# Requires kubectl access to your cluster
./k8sattackmap
```

### Run against saved cluster snapshot

```bash
# First, capture your cluster state
kubectl get pods,services,serviceaccounts,roles,clusterroles,rolebindings,clusterrolebindings,secrets,configmaps,deployments,replicasets,daemonsets,statefulsets,nodes -A -o json > cluster-state.json

# Then run analysis
./k8sattackmap -k cluster-state.json
```

### Example use cases

```bash
# 1. Show all paths between specific source and target nodes
./k8sattackmap -k cluster-state.json \
    -s Pod:default:compromised-app \
    -t Secret:production:db-password \
    --show-all-paths

# 2. Deep blast radius analysis (5-hop radius) with PDF report
./k8sattackmap -k cluster-state.json -m 5 -o pdf

# 3. Multiple sources and targets, both HTML and PDF outputs
./k8sattackmap -k cluster-state.json \
  -s "Pod:default:api-server,ServiceAccount:default:ci-runner" \
  -t "Secret:default:jwt-key,Secret:prod:stripe-key" \
  -o html,pdf
```

> [!CAUTION]
> The source and target node ID format must be `<Type>:<namespace>:<name>`.  
> For cluster-scoped resources, use `cluster-scoped` as the namespace. Example: `ClusterRole:cluster-scoped:cluster-admin`.

> [!TIP]
> Capture your cluster state once and reuse the JSON snapshot for faster offline analysis.

**Output**: HTML visualisation can be opened in your browser; PDF report is written to the current directory.
Both are suitable for sharing with security teams.

---

## Usage

### CLI Reference

```
K8sAttackMap [OPTIONS]

Options:
  -h, --help                   Print this message
  -v, --version                Print version
  -k, --k8s-json <PATH>        Path to Kubernetes cluster state JSON file
  -s, --source-node <IDS>      Comma-separated source node IDs
                               Format: <Type>:<namespace>:<name>
                               Example: Pod:default:web-app
  -t, --target-node <IDS>      Comma-separated target node IDs
                               Format: <Type>:<namespace>:<name>
                               Example: Secret:default:db-credentials
  -o, --output <FORMATS>       Comma-separated output formats: html, pdf
  -m, --max-hops <N>           Blast radius hop depth (default: 3)
  -a, --show-all-paths         Show all discovered paths grouped by
                               source-target pair, not just the worst path
      --no-color               Disable colored output (respects NO_COLOR env var)
      --verbose                Enable verbose/debug logging
```

> [!NOTE]
> When `--source-node` and `--target-node` are omitted, the tool auto-discovers sources (pods, users, service accounts) and targets (secrets, roles, ClusterRoles, sensitive ConfigMaps).

### Examples

```bash
# Offline analysis from a saved cluster snapshot
./k8sattackmap -k cluster-state.json

# Explicit source and target (useful for red-team validation)
./k8sattackmap -k cluster-state.json \
  -s Pod:default:compromised-app \
  -t Secret:production:db-password

# All paths, verbose logging, both outputs
./k8sattackmap -k cluster-state.json --show-all-paths --verbose -o html,pdf

# Multiple sources and targets
./k8sattackmap -k cluster-state.json \
  -s "Pod:default:api-server,ServiceAccount:default:ci-runner" \
  -t "Secret:default:jwt-key,Secret:prod:stripe-key"
  
# Disable colored output for scripting or CI environments
./k8sattackmap -k cluster-state.json --no-color

# Or use the NO_COLOR env var
NO_COLOR=1 ./k8sattackmap -k cluster-state.json
```

---

## Output Formats

### Console (always on)

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/4bbf0e13-0215-49ca-99ac-6f46cb81918e" alt="Console output 1" width="2560" /></td>
    <td><img src="https://github.com/user-attachments/assets/f0408c65-df61-41ce-839f-4c1580d42123" alt="Console output 2" width="2560" /></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/0093dc51-73c4-4810-9c9c-11b03fd02b6f" alt="Console output 3" width="2560" /></td>
    <td><img src="https://github.com/user-attachments/assets/03c3a280-3fe8-4cf1-9ee0-41bc83e45769" alt="Console output 4" width="2560" /></td>
  </tr>
</table>

> [!TIP]
> Use the HTML visualisation for exploratory analysis, and the PDF report for audits or executive reviews.

### HTML (`-o html`) ➔ `k8s-threat-map.html`

Interactive [Cytoscape.js](https://js.cytoscape.org/) graph displaying the attack surface with colour-coded nodes: entry
points bordered in green hexagon, choke points in gray, nodes within blast radius in yellow, and attack paths
highlighted in red. Edges are labelled with their relationship type and weighted by risk score.

<table>
  <tr>
    <td><img width="2560" alt="Graph highlighting nodes within blast radius" src="https://github.com/user-attachments/assets/2f6298f9-fe28-4712-a0bb-1b750c3b1909" /></td>
    <td><img width="2560" alt="Graph showing the most impactful choke point" src="https://github.com/user-attachments/assets/510c620d-e8ec-4b48-a35a-6c1b83680786" /></td>
  </tr>
</table>

### PDF (`-o pdf`) ➔ `k8s-threat-report.pdf`

A structured security audit report containing:

- Executive summary with risk grade and key metrics
- Top-5 choke points with impact percentages
- Critical attack path hop-by-hop table
- Per-choke-point remediation plans with audit and enforcement commands
- Privilege escalation loop table
- Pod CVE summary sorted by count

<img width="1585" alt="Overview of PDF report" src="https://github.com/user-attachments/assets/d621ee50-d25f-4859-90d1-b4c309a5bad5" />

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a detailed breakdown of the source code and test organization, including module responsibilities, design patterns, and testing strategy.

### Core Modules Overview

| Module      | Responsibility                                   |
|-------------|--------------------------------------------------|
| `cli`       | CLI argument parsing and validation              |
| `ingestion` | Kubernetes JSON parsing and live cluster capture |
| `model`     | Core domain types (nodes, edges, graph factory)  |
| `security`  | CVE scanning (Trivy) and edge risk scoring       |
| `analysis`  | Path discovery, choke points, blast radius       |
| `export`    | Console, HTML (Cytoscape), PDF report outputs    |
| `util`      | Shared configuration, constants, helpers         |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, branching strategy, code style guidelines, and the pull request process.

---

## License

[Apache License 2.0](LICENSE)