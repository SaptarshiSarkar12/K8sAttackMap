package io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation;

import java.util.List;

public record RemediationPlan(
            String nodeId,
            String rationale,
            List<String> auditCommands,
            List<String> enforceCommands,
            boolean containsDestructiveAction
    ) {
    }