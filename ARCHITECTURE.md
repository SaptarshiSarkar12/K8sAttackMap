# K8sAttackMap Architecture

This document provides a detailed overview of the K8sAttackMap codebase structure, including both source code and test organization.

## Source Code Structure

```
src/main/java/io/github/SaptarshiSarkar12/k8sattackmap/
│
├── K8sAttackMapApplication.java   # Entry point, wiring
│
├── cli/                           # Argument parsing (Apache Commons CLI)
│   └── CommandParser.java
│
├── ingestion/                     # Cluster data parsing
│   ├── K8sJsonParser.java         # JSON → nodes, edges, SecurityFacts
│   └── KubectlExtractor.java      # Live kubectl capture
│
├── model/                         # Core domain types
│   ├── GraphNode.java             # Vertex with type, namespace, risk score
│   ├── GraphEdge.java             # Edge with EdgeType relationship
│   ├── EdgeType.java              # Enum: USES_SA, BOUND_TO, CAN_ACCESS, …
│   ├── SecurityFacts.java         # RBAC flags, container posture, credential material
│   ├── ClusterGraphFactory.java   # Builds DirectedWeightedMultigraph
│   └── ClusterGraphData.java      # Parser output container
│
├── security/                      # Scanning and scoring
│   ├── AttackSurfaceClassifier.java  # Auto-discovers entry points and targets
│   ├── EdgeRiskScorer.java           # Computes edge weights from CVE/SecurityFacts
│   ├── TrivyScanner.java             # Invokes Trivy CLI
│   └── trivy/                        # Trivy JSON parsing and caching
│       └── TrivyJsonParser.java      # (test: TrivyJsonParserTest.java)
│
├── analysis/                      # Core analysis algorithms
│   ├── AnalysisOrchestrator.java  # Coordinates all analysis stages
│   ├── AnalysisInput.java
│   ├── AnalysisResult.java
│   ├── graph/                     # Path finding
│   │   ├── AttackPathDiscovery.java   # Dijkstra + AllDirectedPaths
│   │   │                              # (test: AttackPathDiscoveryTest.java)
│   │   ├── Dijkstra.java              # (test: DijkstraTest.java)
│   │   ├── PathDiscoveryResult.java
│   │   └── PrivilegeLoopDetector.java # Johnson's cycle detection
│   │                                  # (test: PrivilegeLoopDetectorTest.java)
│   ├── chokepoint/                # Choke point ranking and remediation
│   │   ├── ChokePointIdentifier.java  # (test: ChokePointIdentifierTest.java)
│   │   ├── ChokePointRemediationAdvisor.java
│   │   │                              # (test: ChokePointRemediationAdvisorTest.java)
│   │   ├── ChokePointResult.java
│   │   └── RankedChokePoint.java
│   ├── blast/                     # Blast radius BFS
│   │   ├── BlastRadiusAnalyzer.java   # (test: BlastRadiusAnalyzerTest.java)
│   │   ├── BlastRadiusResult.java
│   │   ├── ImpactedAsset.java
│   │   └── ImpactSeverity.java
│   └── remediation/               # Remediation plan records
│       ├── RemediationPlan.java
│       └── ImpactRemediationAdvisor.java
│           # (test: ImpactRemediationAdvisorTest.java)
│
├── export/                        # Output generation
│   ├── AnalysisSummaryPrinter.java  # Console output
│   ├── CytoscapeExporter.java       # HTML/JS visualisation
│   ├── PdfReportEngine.java         # PDF report
│   └── ExportService.java           # Coordinates export formats
│
└── util/                          # Shared utilities
    ├── AppConstants.java
    ├── ConsoleColors.java
    ├── TerminalCapabilities.java  # Terminal capability detection
    ├── RiskConfig.java            # Centralised risk thresholds
    │                              # (test: RiskConfigTest.java)
    ├── TemplateStore.java         # Runtime-loaded HTML/PDF templates
    ├── JacksonConfig.java         # Shared ObjectMapper
    ├── StringUtils.java           # (test: StringUtilsTest.java)
    ├── NodeFinder.java            # (test: NodeFinderTest.java)
    └── WorkspaceManager.java      # Manages app working directory
```

## Test Structure

Tests mirror the source structure and follow the `*Test.java` naming convention. Key test utilities:

```
src/test/java/io/github/SaptarshiSarkar12/k8sattackmap/
│
├── cli/
│   └── CommandParserTest.java
│
├── ingestion/
│   ├── K8sJsonParserTest.java
│   └── KubectlExtractorTest.java
│
├── model/
│   ├── GraphNodeTest.java
│   └── ClusterGraphFactoryTest.java
│
├── security/
│   ├── EdgeRiskScorerTest.java
│   ├── AttackSurfaceClassifierTest.java
│   └── trivy/
│       └── TrivyJsonParserTest.java
│
├── analysis/
│   ├── graph/
│   │   ├── AttackPathDiscoveryTest.java
│   │   ├── DijkstraTest.java
│   │   └── PrivilegeLoopDetectorTest.java
│   ├── chokepoint/
│   │   ├── ChokePointIdentifierTest.java
│   │   └── ChokePointRemediationAdvisorTest.java
│   ├── blast/
│   │   └── BlastRadiusAnalyzerTest.java
│   └── remediation/
│       └── ImpactRemediationAdvisorTest.java
│
├── util/
│   ├── RiskConfigTest.java
│   ├── NodeFinderTest.java
│   └── StringUtilsTest.java
│
└── helper/
    └── TestGraphHelper.java       # Shared test utilities & fixtures
```

## Key Design Patterns

- **Factory Pattern**: `ClusterGraphFactory` builds the attack graph from parsed resources
- **Strategy Pattern**: Different edge risk scoring strategies based on security facts
- **Orchestrator Pattern**: `AnalysisOrchestrator` coordinates independent analysis phases
- **Graph Algorithms**: Dijkstra for shortest path, Johnson's for cycle detection, BFS for blast radius
- **Fluent Builder**: `AnalysisInput` for configurable analysis parameters

## Testing Strategy

- **Unit Tests**: Isolated component testing with mocks (e.g., `GraphNodeTest`, `DijkstraTest`)
- **Test Fixtures**: `TestGraphHelper` provides reusable mock nodes, edges, and cluster graphs
- **Edge Coverage**: Each analysis module has comprehensive path and scenario coverage

---

For high-level project overview and quick start, see [README.md](README.md).
