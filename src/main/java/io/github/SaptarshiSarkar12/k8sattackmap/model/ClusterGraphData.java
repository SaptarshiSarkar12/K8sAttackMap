package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Setter
@Getter
public class ClusterGraphData {
    private List<GraphNode> nodes;
    private List<GraphEdge> edges;
    private Map<String, List<String>> podCVEIds;
    private Map<String, GraphNode> nodeLookup = new HashMap<>();
}
