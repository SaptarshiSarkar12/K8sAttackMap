package io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import io.github.SaptarshiSarkar12.k8sattackmap.util.RiskConfig;
import org.jgrapht.Graph;
import org.jgrapht.traverse.BreadthFirstIterator;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.containsAny;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.safeLower;

public class BlastRadiusAnalyzer {
    private BlastRadiusAnalyzer() {
    }

    public static List<BlastRadiusResult> analyzeMultiple(Graph<GraphNode, GraphEdge> graph, List<GraphNode> sources, int maxHops) {
        List<BlastRadiusResult> results = new ArrayList<>();
        sources.parallelStream().forEach(source -> {
            BlastRadiusResult result = analyze(graph, source, maxHops);
            synchronized (results) {
                results.add(result);
            }
        });
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
        List<String> reasons = new ArrayList<>();
        String id = safeLower(node.getId());
        String type = safeLower(node.getType());

        double score = 0.0;
        SecurityFacts facts = node.getSecurityFacts();
        boolean matchedFacts = facts != null;

        if (facts != null) {
            score += scoreSecurityFacts(facts, reasons);
            if (score == 0.0) {
                matchedFacts = false;
            }
        }

        double fallbackScore = scoreFallbackHeuristics(id, type, reasons);

        if (matchedFacts) {
            fallbackScore = Math.min(fallbackScore, 8.0);
        }

        score += fallbackScore;
        score -= distancePenalty(hopsFromSource);
        score = Math.clamp(score, 0, 100);

        return new ScoreDetails(score, List.copyOf(reasons));
    }

    private static double scoreSecurityFacts(SecurityFacts facts, List<String> reasons) {
        double score = 0.0;

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

        return score;
    }

    private static double scoreFallbackHeuristics(String id, String type, List<String> reasons) {
        double score = 0.0;

        if (isSecret(id, type)) {
            score += 6;
            reasons.add("Secret entity");
        }
        if (isClusterRoleBinding(id, type)) {
            score += 7;
            reasons.add("Cluster-wide RBAC binding");
        }
        if (isRoleBinding(id, type)) {
            score += 5;
            reasons.add("Namespace RBAC binding");
        }
        if (isServiceAccount(id, type)) {
            score += 4;
            reasons.add("ServiceAccount identity surface");
        }
        if (id.contains("cluster-admin") || id.contains("system:masters")) {
            score += 8;
            reasons.add("Administrative privilege indicator");
        }
        if (containsAny(id, "prod", "production", "vault", "db", "database", "payment", "auth")) {
            score += 4;
            reasons.add("Critical workload or sensitive data");
        }
        if (containsAny(id, "ingress", "loadbalancer", "nodeport", "public", "external")) {
            score += 3;
            reasons.add("External exposure");
        }
        if (isRole(id, type)) {
            score += 4;
            reasons.add("Namespace-scoped RBAC role");
        }
        if (isClusterRole(id, type)) {
            score += 6;
            reasons.add("Cluster-scoped RBAC role");
        }
        if (isPod(id, type)) {
            score += 5;
            reasons.add("Pod execution surface");
        }
        if (isConfigMap(id, type)) {
            score += 3;
            reasons.add("ConfigMap (potential config/credential exposure)");
        }
        if (isGroup(id, type)) {
            score += 4;
            reasons.add("Group identity (broad RBAC subject)");
        }
        if (id.contains("system:serviceaccounts")) {
            score += 5;
            reasons.add("System service account group (broad identity surface)");
        }
        if (id.contains("system:") && (isClusterRole(id, type) || isRole(id, type))) {
            score += 2;
            reasons.add("System-managed RBAC role");
        }

        return score;
    }

    private static boolean isSecret(String id, String type) {
        return type.equals("secret") || id.startsWith("secret:");
    }

    private static boolean isClusterRoleBinding(String id, String type) {
        return type.contains("clusterrolebinding") || id.startsWith("clusterrolebinding:");
    }

    private static boolean isRoleBinding(String id, String type) {
        return type.contains("rolebinding") || id.startsWith("rolebinding:");
    }

    private static boolean isServiceAccount(String id, String type) {
        return type.contains("serviceaccount") || id.startsWith("serviceaccount:");
    }

    private static boolean isRole(String id, String type) {
        return type.equals("role") || id.startsWith("role:");
    }

    private static boolean isClusterRole(String id, String type) {
        return type.equals("clusterrole") || id.startsWith("clusterrole:");
    }

    private static boolean isPod(String id, String type) {
        return type.equals("pod") || id.startsWith("pod:");
    }

    private static boolean isConfigMap(String id, String type) {
        return type.equals("configmap") || id.startsWith("configmap:");
    }

    private static boolean isGroup(String id, String type) {
        return type.equals("group") || id.startsWith("group:");
    }

    private static double distancePenalty(int hopsFromSource) {
        return Math.clamp((hopsFromSource - 1) * 4L, 0, 20);
    }

    private static ImpactSeverity toSeverity(double score) {
        if (score >= RiskConfig.BLAST_SCORE_CRITICAL) return ImpactSeverity.CRITICAL;
        if (score >= RiskConfig.BLAST_SCORE_HIGH) return ImpactSeverity.HIGH;
        if (score >= RiskConfig.BLAST_SCORE_MEDIUM) return ImpactSeverity.MEDIUM;
        return ImpactSeverity.LOW;
    }

    private record ScoreDetails(double score, List<String> reasons) {
    }
}