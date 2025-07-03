import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.HashMap;

public class NetworkEvent {
    private String id;
    private LocalDateTime timestamp;
    private String sourceIP;
    private String destinationIP;
    private int sourcePort;
    private int destinationPort;
    private String protocol;
    private String eventType;
    private String severity;
    private String description;
    private long bytesTransferred;
    private Map<String, String> additionalData;

    public NetworkEvent(String sourceIP, String destinationIP, int sourcePort,
                        int destinationPort, String protocol, String eventType,
                        String severity, String description) {
        this.id = generateEventId();
        this.timestamp = LocalDateTime.now();
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.eventType = eventType;
        this.severity = severity;
        this.description = description;
        this.additionalData = new HashMap<>();
        this.bytesTransferred = 0;
    }

    private String generateEventId() {
        return "EVT-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
    }

    // Getters and Setters
    public String getId() { return id; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getSourceIP() { return sourceIP; }
    public String getDestinationIP() { return destinationIP; }
    public int getSourcePort() { return sourcePort; }
    public int getDestinationPort() { return destinationPort; }
    public String getProtocol() { return protocol; }
    public String getEventType() { return eventType; }
    public String getSeverity() { return severity; }
    public String getDescription() { return description; }
    public long getBytesTransferred() { return bytesTransferred; }
    public Map<String, String> getAdditionalData() { return additionalData; }

    public void setBytesTransferred(long bytes) { this.bytesTransferred = bytes; }
    public void addAdditionalData(String key, String value) {
        this.additionalData.put(key, value);
    }

    public boolean isSuspicious() {
        return severity.equals("HIGH") || severity.equals("CRITICAL") ||
                eventType.contains("MALWARE") || eventType.contains("INTRUSION") ||
                eventType.contains("ANOMALY");
    }

    @Override
    public String toString() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return String.format("[%s] %s | %s:%d -> %s:%d | %s | %s | %s",
                timestamp.format(formatter), severity, sourceIP, sourcePort,
                destinationIP, destinationPort, protocol, eventType, description);
    }
}