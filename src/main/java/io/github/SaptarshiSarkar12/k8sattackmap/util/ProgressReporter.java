package io.github.SaptarshiSarkar12.k8sattackmap.util;

import org.slf4j.Logger;

public final class ProgressReporter {
    private final Logger log;

    public ProgressReporter(Logger log) {
        this.log = log;
    }

    public void stage(String message) {
        System.out.print(ConsoleColors.CYAN_BOLD);
        log.info(message);
        System.out.print(ConsoleColors.RESET);
    }

    public void success(String message) {
        System.out.print(ConsoleColors.GREEN);
        log.info(message);
        System.out.print(ConsoleColors.RESET);
    }

    public void warn(String message) {
        System.out.print(ConsoleColors.YELLOW);
        log.warn(message);
        System.out.print(ConsoleColors.RESET);
    }

    public void error(String message) {
        System.out.print(ConsoleColors.BOLD_RED);
        log.error(message);
        System.out.print(ConsoleColors.RESET);
    }
}