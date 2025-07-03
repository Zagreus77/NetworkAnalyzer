import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Consumer;

public class AlertManager {
    private List<Alert> alerts;
    private Map<String, AlertRule> rules;
    private Set<String> mutedAlerts;
    private Consumer<Alert> alertCallback; // For GUI notifications

    public AlertManager() {
        this.alerts = new ArrayList<>();
        this.rules = new HashMap<>();
        this.mutedAlerts = new HashSet<>();
        initializeDefaultRules();
    }

    // Set callback for GUI alerts
    public void setAlertCallback(Consumer<Alert> callback) {
        this.alertCallback = callback;
    }

    private void initializeDefaultRules() {
        addRule("BRUTE_FORCE", "Multiple failed login attempts", 5, 300);
        addRule("PORT_SCAN", "Port scanning detected", 10, 60);
        addRule("MALWARE_COMM", "Malware communication detected", 1, 1);
        addRule("DATA_EXFILTRATION", "Large data transfer detected", 1, 1);
        addRule("ANOMALY_DETECTED", "Network anomaly detected", 1, 1);
    }

    public void addRule(String name, String description, int threshold, int timeWindowSeconds) {
        rules.put(name, new AlertRule(name, description, threshold, timeWindowSeconds));
    }

    public void processEvent(NetworkEvent event) {
        for (AlertRule rule : rules.values()) {
            if (shouldTriggerAlert(event, rule)) {
                createAlert(event, rule);
            }
        }
    }

    private boolean shouldTriggerAlert(NetworkEvent event, AlertRule rule) {
        if (mutedAlerts.contains(rule.getName())) {
            return false;
        }

        switch (rule.getName()) {
            case "BRUTE_FORCE":
                return event.getEventType().contains("FAILED_LOGIN") ||
                        event.getEventType().contains("AUTH_FAILURE");
            case "PORT_SCAN":
                return event.getEventType().contains("PORT_SCAN") ||
                        event.getEventType().contains("RECON");
            case "MALWARE_COMM":
                return event.getEventType().contains("MALWARE") ||
                        event.getEventType().contains("C2_COMMUNICATION");
            case "DATA_EXFILTRATION":
                return event.getBytesTransferred() > 100000000 ||
                        event.getEventType().contains("DATA_EXFIL");
            case "ANOMALY_DETECTED":
                return event.getEventType().contains("ANOMALY");
            default:
                return false;
        }
    }

    private void createAlert(NetworkEvent event, AlertRule rule) {
        Alert alert = new Alert(
                generateAlertId(),
                rule.getName(),
                rule.getDescription(),
                event.getSeverity(),
                event.getSourceIP(),
                event.getDestinationIP(),
                event.getDescription()
        );

        alerts.add(alert);
        displayAlert(alert);

        // Notify GUI if callback is set
        if (alertCallback != null) {
            alertCallback.accept(alert);
        }
    }

    private String generateAlertId() {
        return "ALT-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
    }

    private void displayAlert(Alert alert) {
        System.out.println("🚨 ALERT TRIGGERED: " + alert);
    }

    public void showActiveAlerts() {
        System.out.println("🚨 Active Alerts (" + alerts.size() + ")");
        System.out.println("==========================================");

        if (alerts.isEmpty()) {
            System.out.println("No active alerts.");
            return;
        }

        alerts.stream()
                .sorted((a1, a2) -> a2.getTimestamp().compareTo(a1.getTimestamp()))
                .limit(10)
                .forEach(System.out::println);
    }

    public void muteAlert(String alertType) {
        mutedAlerts.add(alertType);
        System.out.println("Alert type '" + alertType + "' has been muted.");
    }

    public void unmuteAlert(String alertType) {
        mutedAlerts.remove(alertType);
        System.out.println("Alert type '" + alertType + "' has been unmuted.");
    }

    public List<Alert> getAlerts() { return new ArrayList<>(alerts); }
    public Map<String, AlertRule> getRules() { return new HashMap<>(rules); }
    public int getAlertCount() { return alerts.size(); }

    // Inner classes
    public static class AlertRule {
        private String name;
        private String description;
        private int threshold;
        private int timeWindowSeconds;

        public AlertRule(String name, String description, int threshold, int timeWindowSeconds) {
            this.name = name;
            this.description = description;
            this.threshold = threshold;
            this.timeWindowSeconds = timeWindowSeconds;
        }

        public String getName() { return name; }
        public String getDescription() { return description; }
        public int getThreshold() { return threshold; }
        public int getTimeWindowSeconds() { return timeWindowSeconds; }
    }

    public static class Alert {
        private String id;
        private LocalDateTime timestamp;
        private String alertType;
        private String description;
        private String severity;
        private String sourceIP;
        private String destinationIP;
        private String eventDescription;

        public Alert(String id, String alertType, String description, String severity,
                     String sourceIP, String destinationIP, String eventDescription) {
            this.id = id;
            this.timestamp = LocalDateTime.now();
            this.alertType = alertType;
            this.description = description;
            this.severity = severity;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
            this.eventDescription = eventDescription;
        }

        // Getters for GUI
        public String getId() { return id; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public String getAlertType() { return alertType; }
        public String getDescription() { return description; }
        public String getSeverity() { return severity; }
        public String getSourceIP() { return sourceIP; }
        public String getDestinationIP() { return destinationIP; }
        public String getEventDescription() { return eventDescription; }

        @Override
        public String toString() {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            return String.format("[%s] %s | %s | %s -> %s | %s",
                    timestamp.format(formatter), severity, alertType,
                    sourceIP, destinationIP, eventDescription);
        }
    }
}