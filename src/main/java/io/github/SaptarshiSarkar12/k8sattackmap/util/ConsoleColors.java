package io.github.SaptarshiSarkar12.k8sattackmap.util;

/**
 * Controls ANSI color output for console printing.
 * <p>
 * Color support is automatically detected based on:
 * <ul>
 *     <li>Whether the terminal is interactive (not a CI environment or non-TTY)</li>
 *     <li>NO_COLOR, FORCE_COLOR, CI environment variables</li>
 *     <li>TERM environment variable</li>
 *     <li>--no-color CLI flag</li>
 * </ul>
 * Use {@link TerminalCapabilities#supportsAnsiColors(String[])} to check support.
 */
public final class ConsoleColors {
    private ConsoleColors() {
    }

    public static String RESET = "\u001B[0m";
    public static String BLUE = "\u001B[94m";
    public static String CYAN = "\u001B[36m";
    public static String CYAN_BOLD = "\u001B[1;36m";
    public static String YELLOW = "\u001B[33m";
    public static String BOLD = "\u001B[1m";
    public static String GREEN = "\u001B[92m";
    public static String MAGENTA = "\u001B[95m";
    public static String RED = "\u001B[31m";
    public static String BOLD_RED = "\u001B[1;31m";
    public static String GRAY = "\u001B[90m";

    public static void disableColors() {
        RESET = "";
        BLUE = "";
        CYAN = "";
        CYAN_BOLD = "";
        YELLOW = "";
        BOLD = "";
        GREEN = "";
        MAGENTA = "";
        RED = "";
        BOLD_RED = "";
        GRAY = "";
    }
}
