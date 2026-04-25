package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusAnalyzer;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.ChokePointIdentifier;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.ChokePointRemediationAdvisor;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.ChokePointResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.AttackPathDiscovery;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PathDiscoveryResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PrivilegeLoopDetector;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.RemediationPlan;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.util.ProgressReporter;
import org.jgrapht.GraphPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AnalysisOrchestrator {
    private static final Logger log = LoggerFactory.getLogger(AnalysisOrchestrator.class);
    private static final ProgressReporter progress = new ProgressReporter(log);

    public static AnalysisResult performAnalysis(AnalysisInput input) {
        progress.stage("Starting Kubernetes Attack Path Analysis...");
        PathDiscoveryResult pathDiscoveryResult = AttackPathDiscovery.findAttackPaths(input);
        List<GraphPath<GraphNode, GraphEdge>> allPaths = pathDiscoveryResult.allPossiblePaths();
        progress.success("Attack Path Discovery Completed. " + allPaths.size() + " paths found.");

        progress.stage("Identifying Choke Points...");
        ChokePointResult chokePointResult = ChokePointIdentifier.identifyChokePoints(allPaths);
        int chokePointCount = chokePointResult.rankedChokePoints().size();
        if (chokePointCount == 0) {
            progress.warn("No choke points identified in the attack paths.");
        } else {
            progress.success("Choke Point Identification Completed. " + chokePointCount + " choke points found.");
        }

        progress.stage("Performing Blast Radius Analysis...");
        List<GraphNode> pathSourceNodes = allPaths.stream().map(GraphPath::getStartVertex).distinct().toList();
        List<BlastRadiusResult> blastRadiusResults = BlastRadiusAnalyzer.analyzeMultiple(input.clusterGraph(), pathSourceNodes, input.maxHops());
        progress.success("Blast Radius Analysis Completed. " + blastRadiusResults.size() + " results generated.");

        progress.stage("Detecting Privilege Escalation Loops...");
        List<List<GraphNode>> privilegeLoops = PrivilegeLoopDetector.findEscalationLoops(input.clusterGraph());
        progress.success("Privilege Loop Detection Completed. " + privilegeLoops.size() + " loop(s) found.");

        progress.stage("Generating Remediation Plans...");
        List<RemediationPlan> remediationPlans = ChokePointRemediationAdvisor.buildPlans(chokePointResult, 5);
        progress.success("Remediation Plan Generation Completed. " + remediationPlans.size() + " plans created.");

        return new AnalysisResult(pathDiscoveryResult, blastRadiusResults, chokePointResult, privilegeLoops, remediationPlans);
    }
}
