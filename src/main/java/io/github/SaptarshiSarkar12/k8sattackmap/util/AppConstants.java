package io.github.SaptarshiSarkar12.k8sattackmap.util;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.*;

/**
 * Static application metadata and well-known constant strings.
 * For risk-scoring thresholds see {@link RiskConfig}.
 * For runtime-loaded report templates see {@link TemplateStore}.
 */
public class AppConstants {
    private AppConstants() {}

    public static final String APP_NAME = "K8sAttackMap";
    public static final String APP_VERSION = "v1.0.0";

    public static final String HEADER = BLUE + BOLD + String.format("""
                          ;+;;;;                     d8888 888    888                      888
                       ;;;;;;;;;;;;                 d88888 888    888                      888
                   ;;;;;+;;;;;;;;;;;;;+            d88P888 888    888                      888
                ;;;;+;;;;;+;  ;+;+;;;;;;;;        d88P 888 888888 888888  8888b.   .d8888b 888  888
               ;;;;;;;;;;;:    :;;;+;;;;;;;      d88P  888 888    888        "88b d88P"    888 .88P
              +;;+;  :;            ;:  ;+;;;    d88P   888 888    888    .d888888 888      888888K
              ;;;;;;;   :;;;  ;;;:   ;;;;;+;   d8888888888 Y88b.  Y88b.  888  888 Y88b.    888 "88b
             +;;;;;;:      :  :      :;;;;;;+ d88P     888  "Y888  "Y888 "Y888888  "Y8888P 888  888
             ;;+;+;;  ;;;        ;;;  ;;+;;;;  888b     d888
             ;;;;;;;  :     ;;     :  ;;;;;;;  8888b   d8888
            ;;;;;       :;.    .;:       ;+;;+ 88888b.d88888
            ;;+;;;;;;  :;;  ::  ;;:  ;;;;;;;;; 888Y88888P888  8888b.  88888b.
             +;;;;;;;;     :;;:     ;;;;;;;;+  888 Y888P 888     "88b 888 "88b
               ;+;+;;+;;          ;;;;+;+;+    888  Y8P  888 .d888888 888  888
                +;;;;;;: ;;;;;;;; :;;;;;;+     888   "   888 888  888 888 d88P
                  ;;;;;::;;;;;;;;;:;;;;+       888       888 "Y888888 88888P"
                   +;;;;;+;;;;+;;;;;+;+                               888
                     ;+;;;;+;;;;;;;;;                                 888
             %s                       888
            """, formatVersion() + BLUE) + RESET;

    public static final String FOOTER = BOLD + YELLOW
            + "Example: K8sAttackMap -k cluster.json -s Pod:default:web -t Secret:default:my-secret -o html,pdf"
            + RESET;

    // Well-known namespace for cluster-scoped resources (e.g. ClusterRole, ClusterRoleBinding)
    public static final String CLUSTER_SCOPED = "cluster-scoped";

    // Classpath locations of the report templates (consumed by TemplateStore)
    public static final String HTML_TEMPLATE_RESOURCE_PATH = "/templates/html-template.html";
    public static final String PDF_TEMPLATE_RESOURCE_PATH = "/templates/report-template.html";

    // Output filenames
    public static final String OUTPUT_HTML_FILENAME = "k8s-threat-map.html";
    public static final String OUTPUT_PDF_FILENAME = "k8s-threat-report.pdf";

    private static final int VERSION_WIDTH = 34;

    private static String formatVersion() {
        String color = APP_VERSION.matches("^v\\d+\\.\\d+\\.\\d+$") ? GREEN : MAGENTA;
        int padding = VERSION_WIDTH - APP_VERSION.length();
        int left = padding / 2;
        int right = padding - left;
        return color + " ".repeat(left) + APP_VERSION + " ".repeat(right) + RESET;
    }
}