package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("KubectlExtractor Tests")
class KubectlExtractorTest {
    @Test
    @DisplayName("getClusterContext returns a non-null value")
    void getClusterContextReturnsNonNullValue() {
        assertNotNull(KubectlExtractor.getClusterContext());
    }

    @Test
    @DisplayName("fetchClusterStateAsJson does not throw an exception")
    void fetchClusterStateAsJsonDoesNotThrow() {
        assertDoesNotThrow(KubectlExtractor::fetchClusterStateAsJson);
    }
}