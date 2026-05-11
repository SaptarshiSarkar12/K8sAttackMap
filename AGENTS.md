# AGENTS.md

## K8sAttackMap quick map
- Java 25 Maven CLI for Kubernetes attack-surface analysis.
- Main entrypoint: `src/main/java/io/github/SaptarshiSarkar12/k8sattackmap/K8sAttackMapApplication.java`.
- Core flow: `CommandParser` → `WorkspaceManager`/`TemplateStore` → `KubectlExtractor` or `K8sJsonParser` → `ClusterGraphFactory` → `AnalysisOrchestrator` → `AnalysisSummaryPrinter` + `ExportService` (`CytoscapeExporter`, `PdfReportEngine`).

## Domain model rules that matter
- Node IDs are always `<Type>:<namespace>:<name>`; use `cluster-scoped` for cluster-wide resources.
- `GraphNode`, `GraphEdge`, and `EdgeType` are cross-cutting: parser, scoring, analysis, and exports all depend on them.
- Edge semantics are risk-weighted: lower friction means easier attacker movement, so Dijkstra finds the most dangerous path.
- If you add/change an `EdgeType`, update `K8sJsonParser`, `EdgeRiskScorer`, `AnalysisSummaryPrinter`, and tests together.

## Parsing / scoring conventions
- `K8sJsonParser` builds the graph from a Kubernetes `items` array and caches Trivy image scans.
- `TrivyScanner` shells out to `trivy image --format json --quiet <image>`; runtime requires `trivy` on `PATH`.
- `ClusterGraphFactory` prunes non-entry nodes with zero in-degree; don’t assume every parsed node survives into the graph.
- `AnalysisInput` and `AnalysisResult` are records; prefer immutable payloads at analysis boundaries.

## Output and template conventions
- Console output is deliberate: `System.out` is allowed mainly in `AnalysisSummaryPrinter`.
- HTML/PDF templates live in `src/main/resources/templates/` and are loaded through `TemplateStore`; don’t hardcode report HTML in Java.
- Default export filenames are `k8s-threat-map.html` and `k8s-threat-report.pdf`.

## Developer workflows
- Local test run: `mvn test`.
- Style checks: `mvn checkstyle:check`.
- Build native image: `mvn clean package` (requires GraalVM).
- If reflection/serialization changes affect native image metadata, regenerate `src/main/resources/META-INF/native-image/` using the documented GraalVM agent profile.

## Test patterns
- Tests mirror production packages under `src/test/java/...` and usually use `*Test.java` names.
- Prefer `TestGraphHelper` for synthetic graphs and focused algorithm tests (`Dijkstra`, blast radius, choke points, loops).
- For parser behavior, use minimal JSON fixtures; for analysis behavior, construct `GraphNode`/`GraphEdge` directly.

## Project-specific conventions
- Use 4-space indentation, no tabs.
- Use Lombok and SLF4J consistently (`@Getter`, `@Slf4j`, etc.).
- Keep logging via SLF4J; reserve user-facing summaries for the printer/export layers.
- When changing module access or reflective use, review `src/main/java/module-info.java`.

## Good reference files
- Architecture overview: `ARCHITECTURE.md`
- CLI details: `src/main/java/.../cli/CommandParser.java`
- Graph construction: `src/main/java/.../model/ClusterGraphFactory.java`
- Risk scoring: `src/main/java/.../security/EdgeRiskScorer.java`
- Console/report output: `src/main/java/.../export/AnalysisSummaryPrinter.java`
- Contributor workflow: `CONTRIBUTING.md`
