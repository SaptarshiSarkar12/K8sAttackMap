package io.github.SaptarshiSarkar12.k8sattackmap.util;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.*;

public class CliPrefixConverter extends ClassicConverter {
    @Override
    public String convert(ILoggingEvent event) {
        Level level = event.getLevel();
        String msg = event.getFormattedMessage(); // Grab the actual log message

        return switch (level.toInt()) {
            case Level.ERROR_INT -> BOLD_RED + "✖ ERROR: " + msg + RESET;
            case Level.WARN_INT -> YELLOW + "⚠ WARN:  " + msg + RESET;
            case Level.DEBUG_INT -> GRAY + "⚙ DEBUG: " + msg + RESET;
            default -> msg;
        };
    }
}