/*
 * Copyright 2026 Ivo Rosa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.SaptarshiSarkar12.k8sattackmap.analysis.endpoint;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

import java.util.List;

/**
 * Exposure assessment for one explicitly selected critical endpoint.
 *
 * @param endpointId requested node identifier
 * @param endpoint resolved endpoint, or {@code null} when it is absent
 * @param status reachability state
 * @param depth number of graph hops on the lowest-friction path
 * @param pathCost accumulated attack friction on that path
 * @param alternativePathCount number of discovered paths to the endpoint
 * @param contributingNodes nodes involved in the lowest-friction path
 * @param patchPriorityScore relative score for ordering remediation work
 */
public record CriticalEndpointExposure(
        String endpointId,
        GraphNode endpoint,
        CriticalEndpointStatus status,
        int depth,
        double pathCost,
        long alternativePathCount,
        List<GraphNode> contributingNodes,
        double patchPriorityScore
) {
    public CriticalEndpointExposure {
        contributingNodes = contributingNodes == null ? List.of() : List.copyOf(contributingNodes);
    }
}
