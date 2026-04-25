package io.github.SaptarshiSarkar12.k8sattackmap.util;

import java.util.Locale;

public class StringUtils {
    public static String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    public static boolean containsAny(String value, String... substrings) {
        for (String substring : substrings) {
            if (value.contains(substring)) {
                return true;
            }
        }
        return false;
    }
}
