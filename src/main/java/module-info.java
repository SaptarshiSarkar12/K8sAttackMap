module K8sAttackMap {
    requires ch.qos.logback.classic;
    requires static lombok;
    requires org.apache.commons.cli;
    requires org.slf4j;
    requires com.fasterxml.jackson.databind;
    requires org.jgrapht.core;
    requires openhtmltopdf.pdfbox;
    requires java.logging;
    requires openhtmltopdf.core;

    exports io.github.SaptarshiSarkar12.k8sattackmap.util to ch.qos.logback.core;
}