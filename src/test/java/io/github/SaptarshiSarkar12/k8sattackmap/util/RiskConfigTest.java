package io.github.SaptarshiSarkar12.k8sattackmap.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RiskConfig threshold ordering is internally consistent")
class RiskConfigTest {
    @Test
    @DisplayName("blast score thresholds descend from CRITICAL to MEDIUM above zero")
    void blastScoreThresholdsDescend() {
        Assertions.assertTrue(RiskConfig.BLAST_SCORE_CRITICAL > RiskConfig.BLAST_SCORE_HIGH);
        Assertions.assertTrue(RiskConfig.BLAST_SCORE_HIGH > RiskConfig.BLAST_SCORE_MEDIUM);
        Assertions.assertTrue(RiskConfig.BLAST_SCORE_MEDIUM > 0.0);
    }

    @Test
    @DisplayName("path risk thresholds descend from CRITICAL to MEDIUM above zero")
    void pathRiskThresholdsDescend() {
        Assertions.assertTrue(RiskConfig.PATH_RISK_CRITICAL > RiskConfig.PATH_RISK_HIGH);
        Assertions.assertTrue(RiskConfig.PATH_RISK_HIGH > RiskConfig.PATH_RISK_MEDIUM);
        Assertions.assertTrue(RiskConfig.PATH_RISK_MEDIUM > 0.0);
    }

    @Test
    @DisplayName("blast score thresholds are within a 0-100 scale")
    void blastScoreThresholdsWithinScale() {
        Assertions.assertTrue(RiskConfig.BLAST_SCORE_CRITICAL <= 100.0);
        Assertions.assertTrue(RiskConfig.BLAST_SCORE_HIGH <= 100.0);
        Assertions.assertTrue(RiskConfig.BLAST_SCORE_MEDIUM <= 100.0);
    }

    @Test
    @DisplayName("path risk thresholds are within a 0-10 per-hop scale")
    void pathRiskThresholdsWithinHopScale() {
        Assertions.assertTrue(RiskConfig.PATH_RISK_CRITICAL <= 10.0);
        Assertions.assertTrue(RiskConfig.PATH_RISK_HIGH <= 10.0);
        Assertions.assertTrue(RiskConfig.PATH_RISK_MEDIUM <= 10.0);
    }

    @Test
    @DisplayName("PDF grade critical path count is a positive integer")
    void pdfGradeCriticalPathsIsPositive() {
        Assertions.assertTrue(RiskConfig.PDF_GRADE_CRITICAL_PATHS > 0);
    }
}