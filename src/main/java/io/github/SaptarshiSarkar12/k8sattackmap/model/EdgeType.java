package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Enumeration of edge types representing the semantic relationships between Kubernetes resources.
 * <p>
 * Each edge type defines how resources interact and the risk implications:
 * <ul>
 *   <li>{@link #USES_SA}: Pod/Workload uses a ServiceAccount (identity escalation risk)</li>
 *   <li>{@link #BOUND_TO}: ServiceAccount bound to a Role/ClusterRole (permission grant)</li>
 *   <li>{@link #CAN_ACCESS}: Subject has permission to access/manipulate a resource (RBAC)</li>
 *   <li>{@link #USES_SECRET} / {@link #USES_CONFIGMAP}: Pod mounts or references secrets/configmaps</li>
 *   <li>{@link #MOUNTS_SECRET} / {@link #MOUNTS_CONFIGMAP}: Pod mounts secrets/configmaps as volumes (broader access than env vars)</li>
 *   <li>{@link #MANAGES}: Deployment/StatefulSet manages Pods or ReplicaSets (inheritance)</li>
 *   <li>{@link #NODE_ESCAPE}: Privileged container can escape to node (high-risk escalation)</li>
 *   <li>{@link #HOST_PATH_ACCESS}: Pod has mounted hostPath (node filesystem access)</li>
 *   <li>{@link #EXEC_INTO}: Subject can exec into Pod (lateral movement / shell access)</li>
 *   <li>{@link #ENV_FROM_SECRET} / {@link #ENV_FROM_CONFIGMAP}: Pod reads secrets/configmaps via env vars (data exposure)</li>
 *   <li>{@link #MEMBER_OF}: ServiceAccount is member of a Group (indirect permission grant)</li>
 *   <li>{@link #EXPOSES}: Service exposes a Pod (external access risk)</li>
 *   <li>{@link #EXPOSES_TO_NODE}: Service NodePort/LoadBalancer exposes to Node (broader attack surface)</li>
 * </ul>
 * <p>
 * If you add/change an EdgeType, also update {@link io.github.SaptarshiSarkar12.k8sattackmap.ingestion.K8sJsonParser},
 * {@link io.github.SaptarshiSarkar12.k8sattackmap.security.EdgeRiskScorer},
 * {@link io.github.SaptarshiSarkar12.k8sattackmap.export.AnalysisSummaryPrinter}, and corresponding tests.
 */
@Getter
@RequiredArgsConstructor
public enum EdgeType {
    USES_SA("uses_sa"),
    BOUND_TO("bound_to"),
    CAN_ACCESS("can_access"),
    USES_SECRET("uses_secret"),
    USES_CONFIGMAP("uses_configmap"),
    MOUNTS_SECRET("mounts_secret"),
    MOUNTS_CONFIGMAP("mounts_configmap"),
    MANAGES("manages"), // Deployment -> ReplicaSet -> Pod
    NODE_ESCAPE("node_escape"), // Privileged container escape
    HOST_PATH_ACCESS("host_path_access"),
    MEMBER_OF("member_of"), // ServiceAccount -> Group
    EXPOSES("exposes"), // Service -> Pod
    EXPOSES_TO_NODE("exposes_to_node"), // Service NodePort/LoadBalancer -> Node
    EXEC_INTO("exec_into"), // pods/exec subresource access
    ENV_FROM_SECRET("env_from_secret"), // Pod reads secret via individual env var (valueFrom.secretKeyRef)
    ENV_FROM_CONFIGMAP("env_from_configmap"); // Pod reads configmap via individual env var (valueFrom.configMapKeyRef)

    private final String label;

    @Override
    public String toString() {
        return label;
    }
}