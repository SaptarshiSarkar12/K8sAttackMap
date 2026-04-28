package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.*;
import io.github.SaptarshiSarkar12.k8sattackmap.security.TrivyScanner;
import io.github.SaptarshiSarkar12.k8sattackmap.security.trivy.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Reader;
import java.util.*;

import static io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType.*;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants.*;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.JacksonConfig.MAPPER;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.safeLower;

public class K8sJsonParser {
    private static final Logger log = LoggerFactory.getLogger(K8sJsonParser.class);
    private static final Map<String, ScanResult> imageRiskCache = new HashMap<>(); // Cache for image risk scores to avoid redundant Trivy scans
    private static final Set<String> LATERAL_MOVEMENT_VERBS = Set.of(
            "create", "update", "patch", "delete", "exec",
            "escalate", "bind", "impersonate", "deletecollection"
    );

    public static ClusterGraphData parse(Reader reader) {
        List<GraphEdge> edges = new ArrayList<>();
        Map<String, List<String>> nodesByKindAndNs = new HashMap<>(); // Key: "Kind:namespace" - wildcard RBAC lookups
        Map<String, List<String>> nodesByKindAndName = new HashMap<>(); // Key: "Kind:name" - named-resource RBAC lookups
        Set<String> syntheticNodeIds = new HashSet<>(); // Track User/Group/Node already added
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
            Map<String, List<String>> podCVEIds = buildNodesAndIndex(items, nodes, parsedItems, nodesByKindAndNs, nodesByKindAndName);
            for (ParsedItem item : parsedItems) {
                processEdgesForItem(item, edges, nodes, nodesByKindAndNs, nodesByKindAndName, syntheticNodeIds);
            }
            log.info("Successfully parsed {} resources and scanned {} unique container images.", parsedItems.size(), imageRiskCache.size());
            ClusterGraphData graphData = new ClusterGraphData();
            graphData.setNodes(nodes);
            graphData.setEdges(edges);
            graphData.setPodCVEIds(podCVEIds);
            return graphData;
        } catch (IOException e) {
            log.error("Failed to parse Kubernetes JSON data {}", e.getMessage(), e);
            return null;
        }
    }

    private static void processEdgesForItem(ParsedItem item, List<GraphEdge> edges, List<GraphNode> nodes, Map<String, List<String>> nodesByKindAndNs, Map<String, List<String>> nodesByKindAndName, Set<String> syntheticNodeIds) {
        switch (item.kind()) {
            case "Pod" -> {
                addPodEdges(item, edges, nodes, syntheticNodeIds);
                addOwnershipEdges(item, edges);
            }
            case "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob" -> addOwnershipEdges(item, edges);
            case "RoleBinding", "ClusterRoleBinding" -> addRoleBindingEdges(item, edges, nodes, syntheticNodeIds);
            case "Role", "ClusterRole" -> addRoleEdges(item, edges, nodesByKindAndNs, nodesByKindAndName);
        }
    }

    private static void addRoleEdges(ParsedItem item, List<GraphEdge> edges, Map<String, List<String>> nodesByKindAndNs, Map<String, List<String>> nodesByKindAndName) {
        JsonNode rules = item.raw().path("rules");
        if (!rules.isArray()) return;

        boolean isClusterRole = "ClusterRole".equals(item.kind());
        for (JsonNode rule : rules) {
            // Read-only verbs (get/list/watch) grant API visibility, not lateral movement.
            if (!hasLateralMovementVerb(rule)) continue;
            JsonNode resources = rule.path("resources");
            JsonNode resourceNames = rule.path("resourceNames");
            if (!resources.isArray()) continue;

            for (JsonNode res : resources) {
                String targetKind = mapResourceToKind(res.asText());
                if (targetKind == null) continue;

                if (!resourceNames.isMissingNode() && resourceNames.isArray() && !resourceNames.isEmpty()) {
                    // Named-resource rule: resolve by kind+name regardless of namespace
                    for (JsonNode resName : resourceNames) {
                        String kindNameKey = buildKindNameKey(targetKind, resName.asText());
                        List<String> namedTargets = nodesByKindAndName.getOrDefault(kindNameKey, Collections.emptyList());
                        for (String targetId : namedTargets) {
                            edges.add(createEdge(item.sourceId(), targetId, CAN_ACCESS));
                        }
                    }
                } else if (isClusterRole) {
                    // ClusterRole has no namespace — it can reach resources in ALL namespaces.
                    // Iterate every entry in nodesByKindAndNs whose key starts with "TargetKind:"
                    String prefix = targetKind + ":";
                    for (Map.Entry<String, List<String>> entry : nodesByKindAndNs.entrySet()) {
                        if (entry.getKey().startsWith(prefix)) {
                            for (String targetId : entry.getValue()) {
                                edges.add(createEdge(item.sourceId(), targetId, CAN_ACCESS));
                            }
                        }
                    }
                } else {
                    // Regular Role: namespace-scoped, behavior unchanged
                    String lookupKey = buildKindNsKey(targetKind, item.namespace());
                    List<String> targets = nodesByKindAndNs.getOrDefault(lookupKey, Collections.emptyList());
                    for (String targetId : targets) {
                        edges.add(createEdge(item.sourceId(), targetId, CAN_ACCESS));
                    }
                }
            }
        }
    }

    private static boolean hasLateralMovementVerb(JsonNode rule) {
        JsonNode verbs = rule.path("verbs");
        if (!verbs.isArray()) return false;
        for (JsonNode v : verbs) {
            if ("*".equals(v.asText()) || LATERAL_MOVEMENT_VERBS.contains(v.asText().toLowerCase())) {
                return true;
            }
        }
        return false;
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

            if ("Group".equals(subjKind) && subjName.startsWith("system:serviceaccounts")) {
                String targetNs = null; // null means all namespaces
                if (subjName.startsWith("system:serviceaccounts:")) {
                    targetNs = subjName.substring("system:serviceaccounts:".length());
                }
                final String filterNs = targetNs;
                for (GraphNode node : nodes) {
                    if ("ServiceAccount".equalsIgnoreCase(node.getType())) {
                        // If namespace-scoped group, only expand SAs in that namespace
                        if (filterNs == null || filterNs.equals(node.getNamespace())) {
                            edges.add(createEdge(node.getId(), subjSourceId, MEMBER_OF));
                        }
                    }
                }
            }
            edges.add(createEdge(subjSourceId, roleTargetId, BOUND_TO));
        }
    }

    private static void addPodEdges(ParsedItem item, List<GraphEdge> edges, List<GraphNode> nodes, Set<String> syntheticNodeIds) {
        JsonNode spec = item.raw().path("spec");
        addServiceAccountEdge(item, spec, edges);
        addPodSecretAndConfigMapEdges(item, spec, edges);
        addNodeEscapeEdges(item, spec, edges, nodes, syntheticNodeIds);
    }

    private static void addServiceAccountEdge(ParsedItem item, JsonNode spec, List<GraphEdge> edges) {
        String saName = spec.path("serviceAccountName").asText(null);
        if (saName != null && !saName.isEmpty()) {
            String targetId = buildNodeId("ServiceAccount", item.namespace(), saName);
            edges.add(createEdge(item.sourceId(), targetId, USES_SA));
        }
    }

    private static void addPodSecretAndConfigMapEdges(ParsedItem item, JsonNode spec, List<GraphEdge> edges) {
        JsonNode containers = spec.path("containers");
        if (containers.isArray()) {
            List<String> mountedVolNames = new ArrayList<>();
            for (JsonNode container : containers) {
                JsonNode envFrom = container.path("envFrom");
                if (envFrom.isArray()) {
                    for (JsonNode env : envFrom) {
                        if (env.has("configMapRef")) {
                            String cmName = env.path("configMapRef").path("name").asText(null);
                            if (cmName != null && !cmName.isEmpty()) {
                                String targetId = buildNodeId("ConfigMap", item.namespace(), cmName);
                                edges.add(createEdge(item.sourceId(), targetId, USES_CONFIGMAP));
                            }
                        } else if (env.has("secretRef")) {
                            String secretName = env.path("secretRef").path("name").asText(null);
                            if (secretName != null && !secretName.isEmpty()) {
                                String targetId = buildNodeId("Secret", item.namespace(), secretName);
                                edges.add(createEdge(item.sourceId(), targetId, USES_SECRET));
                            }
                        }
                    }
                }
                JsonNode env = container.path("env");
                if (env.isArray()) {
                    for (JsonNode envVar : env) {
                        JsonNode valueFrom = envVar.path("valueFrom");
                        if (valueFrom.has("secretKeyRef")) {
                            String secretName = valueFrom.path("secretKeyRef").path("name").asText(null);
                            if (secretName != null && !secretName.isEmpty()) {
                                edges.add(createEdge(item.sourceId(),
                                        buildNodeId("Secret", item.namespace(), secretName), ENV_FROM_SECRET));
                            }
                        } else if (valueFrom.has("configMapKeyRef")) {
                            String cmName = valueFrom.path("configMapKeyRef").path("name").asText(null);
                            if (cmName != null && !cmName.isEmpty()) {
                                edges.add(createEdge(item.sourceId(),
                                        buildNodeId("ConfigMap", item.namespace(), cmName), ENV_FROM_CONFIGMAP));
                            }
                        }
                    }
                }
                JsonNode volumeMounts = container.path("volumeMounts");
                if (volumeMounts.isArray()) {
                    for (JsonNode vm : volumeMounts) {
                        String volName = vm.path("name").asText(null);
                        if (volName != null && !volName.isEmpty()) {
                            mountedVolNames.add(volName);
                        }
                    }
                }
            }
            JsonNode volumes = spec.path("volumes");
            if (volumes.isArray()) {
                for (JsonNode vol : volumes) {
                    String volName = vol.path("name").asText(null);
                    // Only process volumes that are actually mounted by a container
                    if (volName == null || !mountedVolNames.contains(volName)) continue;

                    if (vol.has("secret")) {
                        String secretName = vol.path("secret").path("secretName").asText(null);
                        if (secretName != null && !secretName.isEmpty()) {
                            edges.add(createEdge(item.sourceId(), buildNodeId("Secret", item.namespace(), secretName), MOUNTS_SECRET));
                        }
                    } else if (vol.has("configMap")) {
                        String cmName = vol.path("configMap").path("name").asText(null);
                        if (cmName != null && !cmName.isEmpty()) {
                            edges.add(createEdge(item.sourceId(), buildNodeId("ConfigMap", item.namespace(), cmName), MOUNTS_CONFIGMAP));
                        }
                    }
                }
            }
        }
    }

    private static void addNodeEscapeEdges(ParsedItem item, JsonNode spec, List<GraphEdge> edges, List<GraphNode> nodes, Set<String> syntheticNodeIds) {
        String nodeName = spec.path("nodeName").asText(null);
        if (nodeName == null || nodeName.isEmpty()) return;

        String nodeId = buildNodeId("Node", CLUSTER_SCOPED, nodeName);

        // Register the Node as a synthetic node only once, even if multiple pods run on it
        if (syntheticNodeIds.add(nodeId)) {
            GraphNode nodeResource = new GraphNode();
            nodeResource.setId(nodeId);
            nodeResource.setType("Node");
            nodeResource.setNamespace(CLUSTER_SCOPED);
            nodeResource.setRiskScore(0.0);
            SecurityFacts nodeFacts = new SecurityFacts();
            nodeFacts.setNodeLevelSurface(true);
            nodeResource.setSecurityFacts(nodeFacts);
            nodes.add(nodeResource);
        }

        SecurityFacts facts = item.securityFacts();

        if (facts.isPrivilegedContainer()) {
            edges.add(createEdge(item.sourceId(), nodeId, NODE_ESCAPE));
        }
        if (facts.isHostPathMounted()) {
            edges.add(createEdge(item.sourceId(), nodeId, HOST_PATH_ACCESS));
        }
    }

    private static void addOwnershipEdges(ParsedItem item, List<GraphEdge> edges) {
        JsonNode ownerRefs = item.raw().path("metadata").path("ownerReferences");
        if (!ownerRefs.isArray()) return;

        for (JsonNode ref : ownerRefs) {
            String ownerKind = ref.path("kind").asText();
            String ownerName = ref.path("name").asText();
            // Nodes are cluster-scoped; everything else shares the owned resource's namespace
            String ownerNs = "Node".equals(ownerKind) ? CLUSTER_SCOPED : item.namespace();
            String ownerId = buildNodeId(ownerKind, ownerNs, ownerName);
            edges.add(createEdge(ownerId, item.sourceId(), MANAGES));
        }
    }

    private static ScanSummary scanContainerImages(JsonNode item) {
        if (!item.path("kind").asText().equals("Pod")) {
            return ScanSummary.empty();
        }

        JsonNode specContainers = item.path("spec").path("containers");
        JsonNode containerStatuses = item.path("status").path("containerStatuses");
        if (!specContainers.isArray()) {
            return ScanSummary.empty();
        }

        double maxCvssScore = 0.0;
        Set<String> cveIds = new HashSet<>();

        for (JsonNode container : specContainers) {
            String containerName = container.path("name").asText();
            String imageRef = container.path("image").asText();

            // Prefer the resolved imageID from container status (has digest)
            if (containerStatuses.isArray()) {
                for (JsonNode status : containerStatuses) {
                    if (status.path("name").asText().equals(containerName)) {
                        String imageId = status.path("imageID").asText();
                        if (imageId != null && !imageId.isEmpty()) {
                            if (imageId.contains("://")) {
                                imageId = imageId.substring(imageId.indexOf("://") + 3);
                            }
                            imageRef = imageId;
                        }
                        break;
                    }
                }
            }

            if (imageRef != null && !imageRef.isEmpty()) {
                ScanResult scanResult = imageRiskCache.computeIfAbsent(imageRef, TrivyScanner::scanImage);
                List<String> imageCveIds = scanResult.cveIds();
                if (imageCveIds != null) {
                    cveIds.addAll(imageCveIds);
                }
                if (scanResult.cvssScore() > maxCvssScore) {
                    maxCvssScore = scanResult.cvssScore();
                }
            }
        }

        return new ScanSummary(maxCvssScore, cveIds);
    }

    private static void indexNode(ParsedItem parsed, Map<String, List<String>> nodesByKindAndNs, Map<String, List<String>> nodesByKindAndName) {
        nodesByKindAndNs
                .computeIfAbsent(buildKindNsKey(parsed.kind(), parsed.namespace()), _ -> new ArrayList<>())
                .add(parsed.sourceId());
        nodesByKindAndName
                .computeIfAbsent(buildKindNameKey(parsed.kind(), parsed.name()), _ -> new ArrayList<>())
                .add(parsed.sourceId());
    }


    private static Map<String, List<String>> buildNodesAndIndex(
            JsonNode items,
            List<GraphNode> nodes,
            List<ParsedItem> parsedItems,
            Map<String, List<String>> nodesByKindAndNs,
            Map<String, List<String>> nodesByKindAndName) {

        log.info("Extracting workloads and scanning container images via Trivy on-the-fly...");
        Map<String, List<String>> podCVEIds = new HashMap<>();

        for (JsonNode item : items) {
            ScanSummary scan = scanContainerImages(item);
            ParsedItem parsed = parseItemMetadata(item);

            GraphNode node = new GraphNode();
            node.setId(parsed.sourceId());
            node.setType(parsed.kind());
            node.setNamespace(parsed.namespace());
            node.setName(parsed.name());
            node.setRiskScore(scan.maxCvssScore());
            node.setSecurityFacts(parsed.securityFacts());

            nodes.add(node);
            parsedItems.add(parsed);
            podCVEIds.put(parsed.sourceId(), new ArrayList<>(scan.cveIds()));
            indexNode(parsed, nodesByKindAndNs, nodesByKindAndName);
        }

        return podCVEIds;
    }

    private static SecurityFacts extractSecurityFacts(String kind, JsonNode item) {
        SecurityFacts facts = new SecurityFacts();
        String kindLower = kind.toLowerCase();

        switch (kindLower) {
            case "role", "clusterrole" -> extractRbacFacts(item, facts);
            case "pod" -> extractPodFacts(item, facts);
            case "serviceaccount" -> extractServiceAccountFacts(item, facts);
            case "secret" -> extractSecretFacts(item, facts);
            case "node" -> facts.setNodeLevelSurface(true);
            default -> {
                // no-op
            }
        }

        return facts;
    }

    private static void extractRbacFacts(JsonNode item, SecurityFacts facts) {
        JsonNode rules = item.path("rules");
        if (!rules.isArray()) return;

        for (JsonNode rule : rules) {
            JsonNode verbs = rule.path("verbs");
            JsonNode resources = rule.path("resources");
            JsonNode apiGroups = rule.path("apiGroups");

            if (containsWildcard(verbs)) facts.setRbacWildcardVerb(true);
            if (containsWildcard(resources)) facts.setRbacWildcardResource(true);
            if (containsWildcard(apiGroups)) facts.setRbacWildcardApiGroup(true);

            collectLowercaseStrings(verbs, facts.getRbacVerbs());
            collectLowercaseStrings(resources, facts.getRbacResources());
            collectLowercaseStrings(apiGroups, facts.getRbacApiGroups());
        }

        Set<String> verbs = facts.getRbacVerbs();
        facts.setRbacHasEscalate(verbs.contains("escalate"));
        facts.setRbacHasBind(verbs.contains("bind"));
        facts.setRbacHasImpersonate(verbs.contains("impersonate"));
    }

    private static void extractPodFacts(JsonNode item, SecurityFacts facts) {
        JsonNode spec = item.path("spec");

        facts.setHostPID(spec.path("hostPID").asBoolean(false));
        facts.setHostNetwork(spec.path("hostNetwork").asBoolean(false));
        facts.setHostIPC(spec.path("hostIPC").asBoolean(false));

        if (spec.has("automountServiceAccountToken")) {
            facts.setServiceAccountTokenAutomount(spec.path("automountServiceAccountToken").asBoolean(false));
        }

        JsonNode volumes = spec.path("volumes");
        if (volumes.isArray()) {
            for (JsonNode volume : volumes) {
                if (!volume.path("hostPath").isMissingNode()) {
                    facts.setHostPathMounted(true);
                    break;
                }
            }
        }

        extractContainerSecurityFacts(spec.path("containers"), facts);
        extractContainerSecurityFacts(spec.path("initContainers"), facts);
        extractContainerSecurityFacts(spec.path("ephemeralContainers"), facts);
    }

    private static void extractContainerSecurityFacts(JsonNode containers, SecurityFacts facts) {
        if (!containers.isArray()) return;

        for (JsonNode container : containers) {
            JsonNode sc = container.path("securityContext");
            if (sc.isMissingNode()) continue;

            if (sc.path("privileged").asBoolean(false)) {
                facts.setPrivilegedContainer(true);
            }
            if (sc.path("allowPrivilegeEscalation").asBoolean(false)) {
                facts.setAllowPrivilegeEscalation(true);
            }

            if (sc.has("runAsUser") && sc.path("runAsUser").asInt(-1) == 0) {
                facts.setRunAsRoot(true);
            }

            JsonNode capsAdd = sc.path("capabilities").path("add");
            if (capsAdd.isArray()) {
                for (JsonNode cap : capsAdd) {
                    String value = cap.asText("").toLowerCase();
                    if (!value.isBlank() && !facts.getAddedCapabilities().contains(value)) {
                        facts.getAddedCapabilities().add(value);
                    }
                }
            }
        }
    }

    private static void extractServiceAccountFacts(JsonNode item, SecurityFacts facts) {
        JsonNode automount = item.path("automountServiceAccountToken");
        if (!automount.isMissingNode()) {
            facts.setServiceAccountTokenAutomount(automount.asBoolean(false));
        }
    }

    private static void extractSecretFacts(JsonNode item, SecurityFacts facts) {
        String secretType = item.path("type").asText("");
        facts.setSecretType(secretType);

        String lower = secretType.toLowerCase();
        if (lower.contains("service-account-token") || lower.contains("kubernetes.io/tls")
                || lower.contains("dockerconfigjson") || lower.contains("basic-auth")) {
            facts.setCredentialMaterial(true);
        }
    }

    private static boolean containsWildcard(JsonNode arrayNode) {
        if (!arrayNode.isArray()) return false;
        for (JsonNode n : arrayNode) {
            if ("*".equals(n.asText())) return true;
        }
        return false;
    }

    private static void collectLowercaseStrings(JsonNode arrayNode, Set<String> out) {
        if (!arrayNode.isArray()) return;
        for (JsonNode n : arrayNode) {
            String value = n.asText("").toLowerCase();
            if (!value.isBlank()) {
                out.add(value);
            }
        }
    }

    private static GraphEdge createEdge(String source, String target, EdgeType relationship) {
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
        SecurityFacts facts = extractSecurityFacts(kind, item);
        return new ParsedItem(kind, name, namespace, sourceId, item, facts);
    }

    private static String mapResourceToKind(String resourcePlural) {
        String normalized = safeLower(resourcePlural);
        int slashIndex = normalized.indexOf('/');
        String baseResource = slashIndex >= 0 ? normalized.substring(0, slashIndex) : normalized;

        return switch (baseResource) {
            case "secrets" -> "Secret";
            case "configmaps" -> "ConfigMap";
            case "pods" -> "Pod";
            case "services" -> "Service";
            case "deployments" -> "Deployment";
            case "replicasets" -> "ReplicaSet";
            case "statefulsets" -> "StatefulSet";
            case "daemonsets" -> "DaemonSet";
            case "jobs" -> "Job";
            case "cronjobs" -> "CronJob";
            default -> null;
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
            JsonNode raw,
            SecurityFacts securityFacts
    ) {
    }

    private record ScanSummary(double maxCvssScore, Set<String> cveIds) {
        static ScanSummary empty() {
            return new ScanSummary(0.0, Set.of());
        }
    }
}
