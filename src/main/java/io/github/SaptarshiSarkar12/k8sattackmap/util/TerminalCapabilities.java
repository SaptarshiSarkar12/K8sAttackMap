package io.github.SaptarshiSarkar12.k8sattackmap.util;

import java.io.Console;
import java.util.Arrays;

public class TerminalCapabilities {
    private static boolean isTTY() {
        Console console = System.console();
        if (console == null) {
            return false;
        }
        return console.isTerminal();
    }

    public static boolean isCISetToTrue() {
        return Boolean.parseBoolean(System.getenv("CI"));
    }

    public static boolean isNonInteractiveTerminal() {
        return isCISetToTrue() || !isTTY();
    }

    private static boolean isDumbTerm() {
        String term = System.getenv().getOrDefault("TERM", "");
        return term.isEmpty() || term.equals("dumb") || term.equals("unknown");
    }

    public static boolean isEnvVarSet(String varName) {
        String value = System.getenv(varName);
        return value != null && !value.isEmpty();
    }

    public static boolean supportsAnsiColors(String[] args) {
        if (Arrays.asList(args).contains("--no-color")) {
            return false;
        }

        if (isEnvVarSet("NO_COLOR")) {
            return false;
        }

        if (isEnvVarSet("FORCE_COLOR")) {
            return true;
        }

        return !isNonInteractiveTerminal() && !isDumbTerm();
    }
}
