package io.github.SaptarshiSarkar12.k8sattackmap.util;

/**
 * Centralised numeric thresholds used across all risk-scoring and severity
 * classification logic. Changing a value here affects every place that uses it.
 */
public final class RiskConfig {
    private RiskConfig() {}

    // Blast radius impact scoring thresholds (scale 0–100)
    public static final double BLAST_SCORE_CRITICAL = 70.0;
    public static final double BLAST_SCORE_HIGH = 50.0;
    public static final double BLAST_SCORE_MEDIUM = 30.0;

    // Attack path per-hop risk thresholds (scale 0–10 per hop)
    public static final double PATH_RISK_CRITICAL = 8.0;
    public static final double PATH_RISK_HIGH = 6.0;
    public static final double PATH_RISK_MEDIUM = 4.0;

    // PDF report risk grade thresholds (total discovered path count)
    public static final int PDF_GRADE_CRITICAL_PATHS = 10;
}