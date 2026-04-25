module K8sAttackMap {
    // Logging
    requires java.logging;
    requires org.slf4j;
    requires ch.qos.logback.classic;

    // Compile-time only (annotation processor)
    requires static lombok;

    // Third-party libraries
    requires org.apache.commons.cli;
    requires com.fasterxml.jackson.databind;
    requires org.jgrapht.core;
    requires openhtmltopdf.core;
    requires openhtmltopdf.pdfbox;

    // Exports
    exports io.github.SaptarshiSarkar12.k8sattackmap.util to ch.qos.logback.core; // for CliPrefixConverter class
    exports io.github.SaptarshiSarkar12.k8sattackmap.security.trivy to com.fasterxml.jackson.databind; // for deserialization of Trivy ScanResult
    exports io.github.SaptarshiSarkar12.k8sattackmap.model to org.jgrapht.core; // for GraphNode and GraphEdge classes
}