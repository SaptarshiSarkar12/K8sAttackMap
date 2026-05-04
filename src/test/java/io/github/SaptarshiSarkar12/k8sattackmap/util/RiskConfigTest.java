package io.github.SaptarshiSarkar12.k8sattackmap.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RiskConfig threshold ordering is internally consistent")
class RiskConfigTest {
    @Test
    @DisplayName("blast score thresholds descend from CRITICAL to MEDIUM above zero")
    void blastScoreThresholdsDescend() {
        assertTrue(RiskConfig.BLAST_SCORE_CRITICAL > RiskConfig.BLAST_SCORE_HIGH);
        assertTrue(RiskConfig.BLAST_SCORE_HIGH > RiskConfig.BLAST_SCORE_MEDIUM);
        assertTrue(RiskConfig.BLAST_SCORE_MEDIUM > 0.0);
    }

    @Test
    @DisplayName("path risk thresholds descend from CRITICAL to MEDIUM above zero")
    void pathRiskThresholdsDescend() {
        assertTrue(RiskConfig.PATH_RISK_CRITICAL > RiskConfig.PATH_RISK_HIGH);
        assertTrue(RiskConfig.PATH_RISK_HIGH > RiskConfig.PATH_RISK_MEDIUM);
        assertTrue(RiskConfig.PATH_RISK_MEDIUM > 0.0);
    }

    @Test
    @DisplayName("blast score thresholds are within a 0-100 scale")
    void blastScoreThresholdsWithinScale() {
        assertTrue(RiskConfig.BLAST_SCORE_CRITICAL <= 100.0);
        assertTrue(RiskConfig.BLAST_SCORE_HIGH <= 100.0);
        assertTrue(RiskConfig.BLAST_SCORE_MEDIUM <= 100.0);
    }

    @Test
    @DisplayName("path risk thresholds are within a 0-10 per-hop scale")
    void pathRiskThresholdsWithinHopScale() {
        assertTrue(RiskConfig.PATH_RISK_CRITICAL <= 10.0);
        assertTrue(RiskConfig.PATH_RISK_HIGH <= 10.0);
        assertTrue(RiskConfig.PATH_RISK_MEDIUM <= 10.0);
    }

    @Test
    @DisplayName("PDF grade critical path count is a positive integer")
    void pdfGradeCriticalPathsIsPositive() {
        assertTrue(RiskConfig.PDF_GRADE_CRITICAL_PATHS > 0);
    }
}