package io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast;

import org.junit.jupiter.api.Assertions;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import io.github.SaptarshiSarkar12.k8sattackmap.util.RiskConfig;
import org.jgrapht.Graph;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

@DisplayName("BlastRadiusAnalyzer scores and ranks nodes reachable from a compromised source")
class BlastRadiusAnalyzerTest {
    @Test
    @DisplayName("returns empty result when source node is null")
    void shouldReturnEmptyResultForNullSource() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(1);
        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, null, 3);

        Assertions.assertEquals(0, result.totalImpacted());
        Assertions.assertTrue(result.rankedImpactedAssets().isEmpty());
    }

    @Test
    @DisplayName("returns empty result when source is not present in the graph")
    void shouldReturnEmptyResultForSourceNotInGraph() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(1);
        GraphNode outsider = TestGraphHelper.makeNode("Pod:default:outsider", "Pod");

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, outsider, 3);

        Assertions.assertEquals(0, result.totalImpacted());
    }

    @Test
    @DisplayName("returns empty result when maxHops is negative")
    void shouldReturnEmptyResultForNegativeMaxHops() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, source, -1);

        Assertions.assertEquals(0, result.totalImpacted());
    }

    @Test
    @DisplayName("does not include the source node itself in impacted assets")
    void shouldExcludeSourceNodeFromImpactedAssets() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, source, 3);

        boolean sourceInAssets = result.rankedImpactedAssets().stream()
                .anyMatch(a -> a.node().equals(source));
        Assertions.assertFalse(sourceInAssets);
    }

    @Test
    @DisplayName("respects maxHops and does not include nodes beyond the limit")
    void shouldNotIncludeNodesBeyondMaxHops() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(5);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, source, 2);

        for (ImpactedAsset asset : result.rankedImpactedAssets()) {
            Assertions.assertTrue(asset.hopsFromSource() <= 2,
                    "No asset should be further than maxHops=2 from the source");
        }
    }

    @Test
    @DisplayName("node with wildcard RBAC permissions receives CRITICAL severity")
    void shouldAssignCriticalSeverityToWildcardRbacNode() {
        SecurityFacts facts = new SecurityFacts();
        facts.setRbacWildcardVerb(true);
        GraphNode source = TestGraphHelper.makeNode("Pod:default:src", "Pod");
        GraphNode target = TestGraphHelper.makeNodeWithFacts("ClusterRole:cluster-scoped:wildcard", "ClusterRole", 0.0, facts);

        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(
                List.of(source, target),
                List.of(TestGraphHelper.makeEdge(source.getId(), target.getId(), EdgeType.BOUND_TO))
        );

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, source, 3);

        ImpactedAsset asset = result.rankedImpactedAssets().stream()
                .filter(a -> a.node().equals(target))
                .findFirst().orElseThrow();
        Assertions.assertTrue(asset.impactScore() >= RiskConfig.BLAST_SCORE_CRITICAL);
        Assertions.assertEquals(ImpactSeverity.CRITICAL, asset.severity());
    }

    @Test
    @DisplayName("node reached at a greater hop distance has a lower or equal score than at hop 1")
    void shouldApplyDistancePenaltyForHigherHops() {
        // 3-hop linear graph; same type of node at each hop
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(3);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, source, 3);

        ImpactedAsset hop1 = result.rankedImpactedAssets().stream().filter(a -> a.hopsFromSource() == 1).findFirst().orElseThrow();
        ImpactedAsset hop3 = result.rankedImpactedAssets().stream().filter(a -> a.hopsFromSource() == 3).findFirst().orElseThrow();

        Assertions.assertTrue(hop1.impactScore() >= hop3.impactScore(),
                "A node at hop 1 should have a score >= an equivalent node at hop 3");
    }

    @Test
    @DisplayName("results are sorted by impact score descending")
    void shouldSortImpactedAssetsByScoreDescending() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(3);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, source, 3);

        List<ImpactedAsset> assets = result.rankedImpactedAssets();
        for (int i = 1; i < assets.size(); i++) {
            Assertions.assertTrue(assets.get(i - 1).impactScore() >= assets.get(i).impactScore(),
                    "Assets must be sorted by impactScore descending");
        }
    }

    @Test
    @DisplayName("analyzeMultiple returns one result per source node")
    void shouldReturnOneResultPerSource() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        List<GraphNode> sources = graph.vertexSet().stream()
                .filter(n -> n.getId().endsWith("pod-0") || n.getId().endsWith("pod-1"))
                .toList();

        List<BlastRadiusResult> results = BlastRadiusAnalyzer.analyzeMultiple(graph, sources, 3);

        Assertions.assertEquals(sources.size(), results.size());
    }

    @Test
    @DisplayName("severity counts in result reflect the actual severities of impacted assets")
    void severityCountsShouldMatchActualAssets() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        BlastRadiusResult result = BlastRadiusAnalyzer.analyze(graph, source, 3);

        long criticalCount = result.rankedImpactedAssets().stream()
                .filter(a -> a.severity() == ImpactSeverity.CRITICAL).count();
        Assertions.assertEquals(criticalCount, result.severityCounts().get(ImpactSeverity.CRITICAL));
    }
}