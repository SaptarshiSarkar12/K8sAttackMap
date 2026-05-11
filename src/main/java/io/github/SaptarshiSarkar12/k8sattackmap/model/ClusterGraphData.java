package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Container for parsed Kubernetes cluster graph data.
 * <p>
 * Holds all nodes, edges, and metadata extracted from Kubernetes JSON by {@link io.github.SaptarshiSarkar12.k8sattackmap.ingestion.K8sJsonParser}.
 * The {@code nodes} and {@code edges} lists are used to construct the JGraphT graph via {@link ClusterGraphFactory}.
 * <p>
 * {@code podCVEIds} maps Pod IDs to lists of discovered CVE IDs from container image scans (via Trivy).
 * {@code nodeLookup} is populated by {@link ClusterGraphFactory#buildGraph(ClusterGraphData)}
 * for fast O(1) node lookup during edge resolution.
 */
@Setter
@Getter
public class ClusterGraphData {
    private List<GraphNode> nodes;
    private List<GraphEdge> edges;
    private Map<String, List<String>> podCVEIds;
    private Map<String, GraphNode> nodeLookup = new HashMap<>();
}
