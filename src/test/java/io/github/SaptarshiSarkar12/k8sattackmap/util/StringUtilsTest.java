package io.github.SaptarshiSarkar12.k8sattackmap.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("StringUtils provides utility methods for string manipulation")
class StringUtilsTest {
    @Test
    @DisplayName("Test safeLower method")
    public void testSafeLower() {
        Assertions.assertEquals("hello", StringUtils.safeLower("Hello"));
        Assertions.assertEquals("", StringUtils.safeLower(null));
        Assertions.assertEquals("pod:default:web", StringUtils.safeLower("POD:DEFAULT:WEB"));
        // Test with non-ASCII characters
        Assertions.assertEquals("i̇", StringUtils.safeLower("İ")); // Turkish uppercase I with dot lowercases to i with combining dot
    }

    @Test
    @DisplayName("Test containsAny method")
    public void testContainsAny() {
        Assertions.assertTrue(StringUtils.containsAny("hello world", "world", "test"));
        Assertions.assertFalse(StringUtils.containsAny("hello world", "test", "example"));
    }
}
