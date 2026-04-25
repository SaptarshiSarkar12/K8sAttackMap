package io.github.SaptarshiSarkar12.k8sattackmap.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

/**
 * Holds the runtime-loaded HTML/PDF report template strings.
 * Templates are read once at startup via {@link #load(Class)} and
 * are then available as plain fields for the lifetime of the process.
 */
public final class TemplateStore {
    private static final Logger log = LoggerFactory.getLogger(TemplateStore.class);

    private TemplateStore() {}

    public static String HTML;
    public static String PDF;

    /**
     * Loads both templates from the classpath. Exits the process if either
     * template cannot be found, because the application cannot produce any
     * output without them.
     *
     * @param caller the class whose classloader should resolve the resource paths
     */
    public static void load(Class<?> caller) {
        HTML = loadTemplate(caller, AppConstants.HTML_TEMPLATE_RESOURCE_PATH, "HTML");
        PDF  = loadTemplate(caller, AppConstants.PDF_TEMPLATE_RESOURCE_PATH,  "PDF");
    }

    private static String loadTemplate(Class<?> caller, String resourcePath, String label) {
        try {
            return Files.readString(Paths.get(Objects.requireNonNull(caller.getResource(resourcePath)).toURI())
            );
        } catch (Exception e) {
            log.error("Failed to load {} report template from {}: {}", label, resourcePath, e.getMessage(), e);
            System.exit(1);
            return null; // unreachable, but satisfies the compiler
        }
    }
}