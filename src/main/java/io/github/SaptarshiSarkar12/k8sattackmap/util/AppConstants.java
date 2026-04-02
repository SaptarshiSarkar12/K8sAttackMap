package io.github.SaptarshiSarkar12.k8sattackmap.util;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.*;

public class AppConstants {
    private AppConstants() {}

    public static final String APP_NAME = "K8sAttackMap";
    public static final String APP_VERSION = "v1.0.0";
    private static final int VERSION_WIDTH = 34;
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
    public static final String FOOTER = BOLD + YELLOW + "Example: K8sAttackMap -k cluster.json -s Pod:default:web -t Secret:default:my-secret -o html,pdf" + RESET;
    public static final String CLUSTER_SCOPED = "cluster-scoped";
    public static final String USES_SA = "uses_sa";
    public static final String BOUND_TO = "bound_to";
    public static final String CAN_ACCESS = "can_access";
    public static final String HTML_TEMPLATE_RESOURCE_PATH = "/templates/html-template.html";
    public static final String PDF_TEMPLATE_RESOURCE_PATH = "/templates/report-template.html";
    public static final String OUTPUT_HTML_FILENAME = "k8s-threat-map.html";
    public static final String OUTPUT_PDF_FILENAME = "k8s-threat-report.pdf";
    public static String TEMPLATE_HTML;
    public static String TEMPLATE_PDF;

    private static String formatVersion() {
        String color;
        if (APP_VERSION.matches("^v\\d+\\.\\d+\\.\\d+$")) {
            color = GREEN; // Stable versions in green
        } else {
            color = MAGENTA; // Non-standard versions in magenta
        }
        int padding = AppConstants.VERSION_WIDTH - AppConstants.APP_VERSION.length();
        int left = padding / 2;
        int right = padding - left;
        String paddedVersion = " ".repeat(left) + AppConstants.APP_VERSION + " ".repeat(right);
        return color + paddedVersion + RESET;
    }
}
