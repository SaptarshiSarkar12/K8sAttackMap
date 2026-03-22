package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.security.TrivyScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Reader;
import java.util.*;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants.*;

public class K8sJsonParser {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Logger log = LoggerFactory.getLogger(K8sJsonParser.class);
    private static final Map<String, Double> imageRiskCache = new HashMap<>(); // Cache for image risk scores to avoid redundant Trivy scans

    public static ClusterGraphData parse(Reader reader) {
        List<GraphEdge> edges = new ArrayList<>();
        Map<String, List<String>> nodesByKindAndNs = new HashMap<>();   // Key: "Kind:namespace" - wildcard RBAC lookups
        Map<String, List<String>> nodesByKindAndName = new HashMap<>(); // Key: "Kind:name" - named-resource RBAC lookups
        Set<String> syntheticNodeIds = new HashSet<>(); // Track User/Group already added
        try {
            JsonNode items = MAPPER.readTree(reader).path("items");
            if (items.isMissingNode() || !items.isArray()) {
                log.error("Invalid JSON format: 'items' array is missing or not an array.");
                return null;
            }
            int itemsSize = items.size();
            log.debug("Parsing Kubernetes JSON data with {} items.", itemsSize);
            List<GraphNode> nodes = new ArrayList<>(itemsSize);
            List<ParsedItem> parsedItems = new ArrayList<>();
            buildNodesAndIndex(items, nodes, parsedItems, nodesByKindAndNs, nodesByKindAndName);
            for (ParsedItem item : parsedItems) {
                processEdgesForItem(item, edges, nodes, nodesByKindAndNs, nodesByKindAndName, syntheticNodeIds);
            }
            log.info("Successfully parsed {} resources and scanned {} unique container images.", parsedItems.size(), imageRiskCache.size());
            ClusterGraphData graphData = new ClusterGraphData();
            graphData.setNodes(nodes);
            graphData.setEdges(edges);
            return graphData;
        } catch (IOException e) {
            log.error("Failed to parse Kubernetes JSON data {}", e.getMessage(), e);
            return null;
        }
    }

    private static void processEdgesForItem(ParsedItem item, List<GraphEdge> edges, List<GraphNode> nodes, Map<String, List<String>> nodesByKindAndNs, Map<String, List<String>> nodesByKindAndName, Set<String> syntheticNodeIds) {
        switch (item.kind()) {
            case "Pod" -> addPodEdges(item, edges);
            case "RoleBinding", "ClusterRoleBinding" -> addRoleBindingEdges(item, edges, nodes, syntheticNodeIds);
            case "Role", "ClusterRole" -> addRoleEdges(item, edges, nodesByKindAndNs, nodesByKindAndName);
        }
    }

    private static void addRoleEdges(ParsedItem item, List<GraphEdge> edges, Map<String, List<String>> nodesByKindAndNs, Map<String, List<String>> nodesByKindAndName) {
        JsonNode rules = item.raw().path("rules");
        if (rules.isArray()) {
            for (JsonNode rule : rules) {
                JsonNode resources = rule.path("resources");
                JsonNode resourceNames = rule.path("resourceNames");
                if (resources.isArray()) {
                    for (JsonNode res : resources) {
                        String targetKind = mapResourceToKind(res.asText());
                        if (targetKind == null) continue;
                        if (!resourceNames.isMissingNode() && resourceNames.isArray() && !resourceNames.isEmpty()) {
                            for (JsonNode resName : resourceNames) {
                                String kindNameKey = buildKindNameKey(targetKind, resName.asText());
                                List<String> namedTargets = nodesByKindAndName.getOrDefault(kindNameKey, Collections.emptyList());
                                for (String targetId : namedTargets) {
                                    edges.add(createEdge(item.sourceId(), targetId, CAN_ACCESS));
                                }
                            }
                        } else {
                            String lookupKey = buildKindNsKey(targetKind, item.namespace());
                            List<String> targets = nodesByKindAndNs.getOrDefault(lookupKey, Collections.emptyList());
                            for (String targetId : targets) {
                                edges.add(createEdge(item.sourceId(), targetId, CAN_ACCESS));
                            }
                        }
                    }
                }
            }
        }
    }

    private static void addRoleBindingEdges(ParsedItem item, List<GraphEdge> edges, List<GraphNode> nodes, Set<String> syntheticNodeIds) {
        JsonNode roleRef = item.raw().path("roleRef");
        String roleRefKind = roleRef.path("kind").asText();
        String roleRefName = roleRef.path("name").asText();

        String roleNs = roleRefKind.equals("ClusterRole") ? CLUSTER_SCOPED : item.namespace();
        String roleTargetId = buildNodeId(roleRefKind, roleNs, roleRefName);

        JsonNode subjects = item.raw().path("subjects");
        if (!subjects.isArray()) return;

        for (JsonNode subject : subjects) {
            String subjKind = subject.path("kind").asText();
            String subjName = subject.path("name").asText();
            String subjNs = ("User".equals(subjKind) || "Group".equals(subjKind))
                    ? CLUSTER_SCOPED
                    : subject.path("namespace").asText(item.namespace());
            String subjSourceId = buildNodeId(subjKind, subjNs, subjName);

            // Register User/Group as synthetic nodes since they don't exist as K8s items
            if (("User".equals(subjKind) || "Group".equals(subjKind)) && syntheticNodeIds.add(subjSourceId)) {
                GraphNode syntheticNode = new GraphNode();
                syntheticNode.setId(subjSourceId);
                syntheticNode.setType(subjKind);
                syntheticNode.setNamespace(subjNs);
                syntheticNode.setRiskScore(0.0);
                nodes.add(syntheticNode);
            }

            edges.add(createEdge(subjSourceId, roleTargetId, BOUND_TO));
        }
    }

    private static void addPodEdges(ParsedItem item, List<GraphEdge> edges) {
        String saName = item.raw().path("spec").path("serviceAccountName").asText(null);
        if (saName != null && !saName.isEmpty()) {
            String targetId = buildNodeId("ServiceAccount", item.namespace(), saName);
            edges.add(createEdge(item.sourceId(), targetId, USES_SA));
        }
    }

    private static void buildNodesAndIndex(JsonNode items, List<GraphNode> nodes, List<ParsedItem> parsedItems, Map<String, List<String>> nodesByKindAndNs, Map<String, List<String>> nodesByKindAndName) {
        log.info("Extracting workloads and scanning container images via Trivy on-the-fly...");
        for (JsonNode item : items) {
            double maxRiskScore = 0.0;
            if (item.path("kind").asText().equals("Pod")) {
                JsonNode containers = item.path("spec").path("containers");
                if (containers.isArray()) {
                    for (JsonNode container : containers) {
                        String image = container.path("image").asText();
                        if (!image.isEmpty()) {
                            double riskScore = imageRiskCache.computeIfAbsent(image, TrivyScanner::scanImage);
                            if (riskScore > maxRiskScore) {
                                maxRiskScore = riskScore;
                            }
                        }
                    }
                }
            }
            ParsedItem parsed = parseItemMetadata(item);
            parsedItems.add(parsed);
            GraphNode node = new GraphNode();
            node.setId(parsed.sourceId());
            node.setType(parsed.kind());
            node.setNamespace(parsed.namespace());
            node.setRiskScore(maxRiskScore);
            nodes.add(node);
            // Index by Kind+Namespace for wildcard RBAC rules (e.g., "Secret:default")
            String kindNsKey = buildKindNsKey(parsed.kind(), parsed.namespace());
            nodesByKindAndNs.computeIfAbsent(kindNsKey, _ -> new ArrayList<>()).add(parsed.sourceId());
            // Index by Kind+Name for named-resource RBAC rules (e.g., "Secret:my-secret")
            String kindNameKey = buildKindNameKey(parsed.kind(), parsed.name());
            nodesByKindAndName.computeIfAbsent(kindNameKey, _ -> new ArrayList<>()).add(parsed.sourceId());
        }
    }

    private static GraphEdge createEdge(String source, String target, String relationship) {
        GraphEdge edge = new GraphEdge();
        edge.setSource(source);
        edge.setTarget(target);
        edge.setRelationship(relationship);
        return edge;
    }

    private static ParsedItem parseItemMetadata(JsonNode item) {
        String kind = item.path("kind").asText();
        JsonNode metadata = item.path("metadata");
        String name = metadata.path("name").asText();
        String namespace = metadata.path("namespace").asText(CLUSTER_SCOPED);
        String sourceId = buildNodeId(kind, namespace, name);
        return new ParsedItem(kind, name, namespace, sourceId, item);
    }

    private static String mapResourceToKind(String resourcePlural) {
        return switch (resourcePlural.toLowerCase()) {
            case "secrets" -> "Secret";
            case "configmaps" -> "ConfigMap";
            case "pods" -> "Pod";
            case "services" -> "Service";
            case "deployments" -> "Deployment";
            default -> null; // We ignore resources we don't care about mapping
        };
    }

    private static String buildNodeId(String kind, String namespace, String name) {
        return kind + ":" + namespace + ":" + name;
    }

    private static String buildKindNsKey(String kind, String namespace) {
        return kind + ":" + namespace;
    }

    private static String buildKindNameKey(String kind, String name) {
        return kind + ":" + name;
    }

    private record ParsedItem(
            String kind,
            String name,
            String namespace,
            String sourceId,
            JsonNode raw
    ) {
    }
}
