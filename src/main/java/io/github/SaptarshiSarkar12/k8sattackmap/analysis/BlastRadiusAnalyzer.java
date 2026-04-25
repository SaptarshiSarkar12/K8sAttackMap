package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import org.jgrapht.Graph;
import org.jgrapht.traverse.BreadthFirstIterator;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisStringUtils.containsAny;
import static io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisStringUtils.safeLower;

public class BlastRadiusAnalyzer {
    private BlastRadiusAnalyzer() {
    }

    public static List<BlastRadiusResult> analyzeMultiple(Graph<GraphNode, GraphEdge> graph, List<GraphNode> sources, int maxHops) {
        List<BlastRadiusResult> results = new ArrayList<>();
        for (GraphNode source : sources) {
            BlastRadiusResult result = analyze(graph, source, maxHops);
            results.add(result);
        }
        return results;
    }

    public static BlastRadiusResult analyze(Graph<GraphNode, GraphEdge> graph, GraphNode source, int maxHops) {
        if (source == null || !graph.containsVertex(source) || maxHops < 0) {
            return emptyResult(source, maxHops);
        }

        BreadthFirstIterator<GraphNode, GraphEdge> iterator = new BreadthFirstIterator<>(graph, source);
        Map<GraphNode, Integer> distanceMap = new HashMap<>();

        while (iterator.hasNext()) {
            GraphNode node = iterator.next();
            int depth = iterator.getDepth(node);
            if (depth > maxHops) {
                continue;
            }
            distanceMap.put(node, depth);
        }

        List<ImpactedAsset> impactedAssets = new ArrayList<>();
        for (Map.Entry<GraphNode, Integer> entry : distanceMap.entrySet()) {
            GraphNode node = entry.getKey();
            int hopsFromSource = entry.getValue();

            if (node.equals(source)) {
                continue;
            }

            ScoreDetails score = scoreNode(node, hopsFromSource);
            impactedAssets.add(new ImpactedAsset(node, hopsFromSource, score.score(), toSeverity(score.score()), score.reasons()));
        }

        impactedAssets.sort(
                Comparator.comparingDouble(ImpactedAsset::impactScore).reversed()
                        .thenComparing(a -> a.node().getId(), String.CASE_INSENSITIVE_ORDER)
        );

        Map<ImpactSeverity, Long> severityCounts = buildSeverityCounts(impactedAssets);
        return new BlastRadiusResult(source, maxHops, impactedAssets.size(), severityCounts, impactedAssets);
    }

    private static BlastRadiusResult emptyResult(GraphNode source, int maxHops) {
        return new BlastRadiusResult(source, maxHops, 0, getDefaultSeverityMap(), List.of());
    }

    private static Map<ImpactSeverity, Long> buildSeverityCounts(List<ImpactedAsset> assets) {
        Map<ImpactSeverity, Long> counts = getDefaultSeverityMap();
        for (ImpactedAsset asset : assets) {
            counts.put(asset.severity(), counts.get(asset.severity()) + 1);
        }
        return counts;
    }

    private static Map<ImpactSeverity, Long> getDefaultSeverityMap() {
        Map<ImpactSeverity, Long> counts = new EnumMap<>(ImpactSeverity.class);
        counts.put(ImpactSeverity.CRITICAL, 0L);
        counts.put(ImpactSeverity.HIGH, 0L);
        counts.put(ImpactSeverity.MEDIUM, 0L);
        counts.put(ImpactSeverity.LOW, 0L);
        return counts;
    }

    private static ScoreDetails scoreNode(GraphNode node, int hopsFromSource) {
        /*
         * TODO: Check the new scoreNode method implementation and check the copilot chat
         *  for modified improvements for AttackSurfaceClassifier
         * | Entity or pattern | Suggested reason text | Typical weight |
         * |---|---|---|
         * | role / role: | Namespace RBAC permission definition | +20 to +25 |
         * | clusterrole / clusterrole: | Cluster-wide RBAC permission definition | +30 to +40 |
         * | user / user: | Direct user principal access path | +20 to +30 |
         * | group / group: | Group principal privilege aggregation | +20 to +30 |
         * | system:masters / admin groups | Administrative group membership exposure | +40 |
         * | wildcard RBAC indicators like \* in id/name | Wildcard RBAC permissions | +35 to +45 |
         * | escalate, bind, impersonate | Privilege escalation verb exposure | +35 to +45 |
         * | token, sa-token, kubeconfig, cert, key | Credential material exposure | +30 to +40 |
         * | node / kubelet | Node-level execution surface | +30 |
         * | pod with exec/shell indicators | Workload runtime execution surface | +20 to +30 |
         *
         * For your specific ask, the minimum missing reasons are:
         * 1. Role -> Namespace RBAC permission definition
         * 2. User -> Direct user principal access path
         * 3. Also add ClusterRole and Group checks to avoid RBAC blind spots.
         */
        List<String> reasons = new ArrayList<>();
        String id = safeLower(node.getId());
        String type = safeLower(node.getType());

        double score = 0.0;

        SecurityFacts facts = node.getSecurityFacts();
        boolean matchedFacts = true;

        // Metadata-driven scoring first
        if (facts != null) {
            if (facts.isRbacWildcardVerb() || facts.isRbacWildcardResource() || facts.isRbacWildcardApiGroup()) {
                score += 40;
                reasons.add("Wildcard RBAC permissions");
            }
            if (facts.isRbacHasEscalate() || facts.isRbacHasBind() || facts.isRbacHasImpersonate()) {
                score += 40;
                reasons.add("Privilege escalation RBAC verbs");
            }
            if (facts.isCredentialMaterial()) {
                score += 35;
                reasons.add("Credential material exposure");
            }
            if (facts.isServiceAccountTokenAutomount()) {
                score += 20;
                reasons.add("ServiceAccount token auto-mount enabled");
            }
            if (facts.isPrivilegedContainer()) {
                score += 30;
                reasons.add("Privileged container runtime");
            }
            if (facts.isAllowPrivilegeEscalation()) {
                score += 25;
                reasons.add("Container allows privilege escalation");
            }
            if (facts.isHostPID() || facts.isHostNetwork() || facts.isHostIPC()) {
                score += 25;
                reasons.add("Host namespace exposure (PID/Network/IPC)");
            }
            if (facts.isHostPathMounted()) {
                score += 20;
                reasons.add("HostPath mount exposure");
            }
            if (facts.isRunAsRoot()) {
                score += 15;
                reasons.add("Container running as root");
            }
            if (facts.isNodeLevelSurface()) {
                score += 30;
                reasons.add("Node-level execution surface");
            }
            if (facts.getAddedCapabilities() != null && !facts.getAddedCapabilities().isEmpty()) {
                score += 15;
                reasons.add("Added Linux capabilities");
            }
        }
        if (score == 0) {
            matchedFacts = false;
        }

        // fallback heuristics
        double fallbackScore = 0.0;

        if (type.equals("secret") || id.startsWith("secret:")) {
            fallbackScore += 6;
            reasons.add("Secret entity");
        }
        if (type.contains("clusterrolebinding") || id.startsWith("clusterrolebinding:")) {
            fallbackScore += 7;
            reasons.add("Cluster-wide RBAC binding");
        }
        if (type.contains("rolebinding") || id.startsWith("rolebinding:")) {
            fallbackScore += 5;
            reasons.add("Namespace RBAC binding");
        }
        if (type.contains("serviceaccount") || id.startsWith("serviceaccount:")) {
            fallbackScore += 4;
            reasons.add("ServiceAccount identity surface");
        }
        if (id.contains("cluster-admin") || id.contains("system:masters")) {
            fallbackScore += 8;
            reasons.add("Administrative privilege indicator");
        }
        if (containsAny(id, "prod", "production", "vault", "db", "database", "payment", "auth")) {
            fallbackScore += 4;
            reasons.add("Critical workload or sensitive data");
        }
        if (containsAny(id, "ingress", "loadbalancer", "nodeport", "public", "external")) {
            fallbackScore += 3;
            reasons.add("External exposure");
        }

        // if facts matched, keep fallback from dominating
        if (matchedFacts) {
            fallbackScore = Math.min(fallbackScore, 8.0);
        }

        score += fallbackScore;

        // Distance penalty
        double penalty = Math.clamp((hopsFromSource - 1) * 4L, 0, 20);
        score -= penalty;

        score = Math.clamp(score, 0, 100);
        return new ScoreDetails(score, List.copyOf(reasons));
    }

    private static ImpactSeverity toSeverity(double score) {
        if (score >= 70) return ImpactSeverity.CRITICAL;
        if (score >= 50) return ImpactSeverity.HIGH;
        if (score >= 30) return ImpactSeverity.MEDIUM;
        return ImpactSeverity.LOW;
    }

    private record ScoreDetails(double score, List<String> reasons) {
    }
}