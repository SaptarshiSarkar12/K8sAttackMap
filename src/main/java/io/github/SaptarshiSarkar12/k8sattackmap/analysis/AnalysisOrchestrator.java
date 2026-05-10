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
import lombok.extern.slf4j.Slf4j;
import org.jgrapht.GraphPath;

import java.util.List;

@Slf4j
public class AnalysisOrchestrator {
    private static final ProgressReporter PROGRESS_REPORTER = new ProgressReporter(log);

    public static AnalysisResult performAnalysis(AnalysisInput input) {
        PROGRESS_REPORTER.stage("Starting Kubernetes Attack Path Analysis...");
        PathDiscoveryResult pathDiscoveryResult = AttackPathDiscovery.findAttackPaths(input);
        List<GraphPath<GraphNode, GraphEdge>> allPaths = pathDiscoveryResult.allPossiblePaths();
        PROGRESS_REPORTER.success("Attack Path Discovery Completed. " + allPaths.size() + " paths found.");

        PROGRESS_REPORTER.stage("Identifying Choke Points...");
        ChokePointResult chokePointResult = ChokePointIdentifier.identifyChokePoints(allPaths);
        int chokePointCount = chokePointResult.rankedChokePoints().size();
        if (chokePointCount == 0) {
            PROGRESS_REPORTER.warn("No choke points identified in the attack paths.");
        } else {
            PROGRESS_REPORTER.success("Choke Point Identification Completed. " + chokePointCount + " choke points found.");
        }

        PROGRESS_REPORTER.stage("Performing Blast Radius Analysis...");
        List<GraphNode> pathSourceNodes = allPaths.stream().map(GraphPath::getStartVertex).distinct().toList();
        List<BlastRadiusResult> blastRadiusResults = BlastRadiusAnalyzer.analyzeMultiple(input.clusterGraph(), pathSourceNodes, input.maxHops());
        PROGRESS_REPORTER.success("Blast Radius Analysis Completed. " + blastRadiusResults.size() + " results generated.");

        PROGRESS_REPORTER.stage("Detecting Privilege Escalation Loops...");
        List<List<GraphNode>> privilegeLoops = PrivilegeLoopDetector.findEscalationLoops(input.clusterGraph());
        PROGRESS_REPORTER.success("Privilege Loop Detection Completed. " + privilegeLoops.size() + " loop(s) found.");

        PROGRESS_REPORTER.stage("Generating Remediation Plans...");
        List<RemediationPlan> remediationPlans = ChokePointRemediationAdvisor.buildPlans(chokePointResult, 5);
        PROGRESS_REPORTER.success("Remediation Plan Generation Completed. " + remediationPlans.size() + " plans created.");

        return new AnalysisResult(pathDiscoveryResult, blastRadiusResults, chokePointResult, privilegeLoops, remediationPlans);
    }
}
