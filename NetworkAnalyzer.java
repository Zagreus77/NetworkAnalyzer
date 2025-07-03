import java.util.*;
import java.util.stream.Collectors;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.io.*;
import java.util.function.Consumer;

public class NetworkAnalyzer {
    private List<NetworkEvent> events;
    private Map<String, Integer> threatCounter;
    private Map<String, Integer> ipCounter;
    private Map<String, Integer> portCounter;
    private Map<String, Long> protocolStats;
    private AlertManager alertManager;
    private boolean isMonitoring;
    private ThreatIntelligence threatIntel;
    private NetworkStatistics stats;
    private Consumer<NetworkEvent> eventCallback; // For GUI notifications
    private Thread monitoringThread;

    public NetworkAnalyzer() {
        this.events = new ArrayList<>();
        this.threatCounter = new HashMap<>();
        this.ipCounter = new HashMap<>();
        this.portCounter = new HashMap<>();
        this.protocolStats = new HashMap<>();
        this.alertManager = new AlertManager();
        this.isMonitoring = false;
        this.threatIntel = new ThreatIntelligence();
        this.stats = new NetworkStatistics();
        initializeSampleData();
    }

    // Set callback for GUI event notifications
    public void setEventCallback(Consumer<NetworkEvent> callback) {
        this.eventCallback = callback;
    }

    // Get methods for GUI
    public List<NetworkEvent> getEvents() { return new ArrayList<>(events); }
    public Map<String, Integer> getThreatCounter() { return new HashMap<>(threatCounter); }
    public Map<String, Integer> getIpCounter() { return new HashMap<>(ipCounter); }
    public AlertManager getAlertManager() { return alertManager; }
    public boolean isMonitoring() { return isMonitoring; }
    public NetworkStatistics getStats() { return stats; }

    public void startNetworkMonitoring() {
        if (isMonitoring) return; // Already monitoring

        this.isMonitoring = true;
        monitoringThread = new Thread(() -> {
            while (isMonitoring) {
                try {
                    NetworkEvent event = generateSimulatedNetworkEvent();
                    processNetworkEvent(event);
                    Thread.sleep(1000 + (int)(Math.random() * 2000));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });

        monitoringThread.setDaemon(true);
        monitoringThread.start();
    }

    public void stopNetworkMonitoring() {
        this.isMonitoring = false;
        if (monitoringThread != null) {
            monitoringThread.interrupt();
        }
    }

    private NetworkEvent generateSimulatedNetworkEvent() {
        String[] eventTypes = {
                "NORMAL_TRAFFIC", "HTTP_REQUEST", "HTTPS_REQUEST", "DNS_QUERY",
                "FAILED_LOGIN", "PORT_SCAN", "MALWARE_COMM", "DATA_EXFIL",
                "ANOMALY_DETECTED", "INTRUSION_ATTEMPT", "C2_COMMUNICATION"
        };

        String[] protocols = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"};

        String sourceIP = generateRandomIP();
        String destIP = generateRandomIP();
        String eventType = eventTypes[(int)(Math.random() * eventTypes.length)];
        String severity = determineSeverity(eventType);
        String protocol = protocols[(int)(Math.random() * protocols.length)];

        int sourcePort = (int)(Math.random() * 65535) + 1;
        int destPort = getRealisticDestPort(protocol);
        String description = generateEventDescription(eventType, sourceIP, destIP);

        NetworkEvent event = new NetworkEvent(sourceIP, destIP, sourcePort, destPort,
                protocol, eventType, severity, description);

        if (eventType.contains("DATA_EXFIL")) {
            event.setBytesTransferred(50000000 + (long)(Math.random() * 200000000));
        } else {
            event.setBytesTransferred((long)(Math.random() * 10000));
        }

        return event;
    }

    private String generateRandomIP() {
        String[] ipRanges = {
                "192.168.1.", "10.0.0.", "172.16.0.", "203.0.113.", "198.51.100."
        };
        String range = ipRanges[(int)(Math.random() * ipRanges.length)];
        return range + (int)(Math.random() * 254 + 1);
    }

    private String determineSeverity(String eventType) {
        switch (eventType) {
            case "MALWARE_COMM":
            case "C2_COMMUNICATION":
            case "DATA_EXFIL":
                return "CRITICAL";
            case "INTRUSION_ATTEMPT":
            case "PORT_SCAN":
                return "HIGH";
            case "FAILED_LOGIN":
            case "ANOMALY_DETECTED":
                return "MEDIUM";
            default:
                return "LOW";
        }
    }

    private int getRealisticDestPort(String protocol) {
        Map<String, int[]> commonPorts = Map.of(
                "HTTP", new int[]{80, 8080, 3000, 8000},
                "HTTPS", new int[]{443, 8443},
                "DNS", new int[]{53},
                "TCP", new int[]{21, 22, 23, 25, 80, 443, 993, 995},
                "UDP", new int[]{53, 67, 68, 123, 161}
        );

        int[] ports = commonPorts.getOrDefault(protocol, new int[]{80, 443, 22, 21});
        return ports[(int)(Math.random() * ports.length)];
    }

    private String generateEventDescription(String eventType, String sourceIP, String destIP) {
        switch (eventType) {
            case "MALWARE_COMM":
                return "Suspected malware communication detected from " + sourceIP;
            case "PORT_SCAN":
                return "Port scanning activity detected from " + sourceIP;
            case "FAILED_LOGIN":
                return "Failed authentication attempt from " + sourceIP;
            case "DATA_EXFIL":
                return "Large data transfer detected: " + sourceIP + " -> " + destIP;
            case "INTRUSION_ATTEMPT":
                return "Potential intrusion attempt from " + sourceIP;
            case "C2_COMMUNICATION":
                return "Command & Control communication detected: " + sourceIP;
            case "ANOMALY_DETECTED":
                return "Network anomaly detected involving " + sourceIP;
            default:
                return "Network traffic: " + sourceIP + " -> " + destIP;
        }
    }

    private void processNetworkEvent(NetworkEvent event) {
        events.add(event);
        updateCounters(event);
        threatIntel.analyzeEvent(event);
        alertManager.processEvent(event);
        stats.updateStats(event);

        // Notify GUI if callback is set
        if (eventCallback != null) {
            eventCallback.accept(event);
        }
    }

    private void updateCounters(NetworkEvent event) {
        threatCounter.merge(event.getEventType(), 1, Integer::sum);
        ipCounter.merge(event.getSourceIP(), 1, Integer::sum);
        portCounter.merge(String.valueOf(event.getDestinationPort()), 1, Integer::sum);
        protocolStats.merge(event.getProtocol(), event.getBytesTransferred(), Long::sum);
    }

    // Keep the original console methods for backward compatibility
    public void analyzeTrafficLogs() {
        System.out.println("📊 Analyzing Network Traffic Logs...");
        // ... existing implementation
    }

    public void showSecurityDashboard() {
        System.out.println("🛡️  SOC Security Dashboard");
        // ... existing implementation
    }

    public void generateThreatReport() {
        System.out.println("📋 Generating Threat Intelligence Report...");
        // ... existing implementation
    }

    public void configureAlerts() {
        System.out.println("⚙️  Alert Configuration");
        // ... existing implementation
    }

    public void showStatistics() {
        System.out.println("📊 Network Statistics");
        stats.displayStatistics();
    }

    // GUI-specific methods
    public String getSecurityStatus() {
        long totalEvents = events.size();
        long criticalEvents = events.stream()
                .filter(e -> e.getSeverity().equals("CRITICAL")).count();

        if (totalEvents == 0) return "UNKNOWN";
        double riskRatio = (double) criticalEvents / totalEvents;
        if (riskRatio > 0.1) return "CRITICAL";
        if (riskRatio > 0.05) return "HIGH";
        if (riskRatio > 0.02) return "MEDIUM";
        return "LOW";
    }

    public long getSuspiciousEventCount() {
        return events.stream().filter(NetworkEvent::isSuspicious).count();
    }

    public long getCriticalEventCount() {
        return events.stream().filter(e -> e.getSeverity().equals("CRITICAL")).count();
    }

    private void initializeSampleData() {
        String[] sampleIPs = {"192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10"};
        String[] sampleEvents = {"NORMAL_TRAFFIC", "FAILED_LOGIN", "PORT_SCAN", "MALWARE_COMM"};

        for (int i = 0; i < 10; i++) {
            String sourceIP = sampleIPs[i % sampleIPs.length];
            String destIP = sampleIPs[(i + 1) % sampleIPs.length];
            String eventType = sampleEvents[i % sampleEvents.length];

            NetworkEvent event = new NetworkEvent(sourceIP, destIP,
                    1000 + i, 80, "TCP",
                    eventType, determineSeverity(eventType),
                    "Sample " + eventType + " event");

            events.add(event);
            updateCounters(event);
        }
    }

    // Helper classes (same as before)
    private static class ThreatIntelligence {
        private Set<String> knownMaliciousIPs;

        public ThreatIntelligence() {
            this.knownMaliciousIPs = new HashSet<>();
            initializeThreatData();
        }

        private void initializeThreatData() {
            knownMaliciousIPs.add("198.51.100.1");
            knownMaliciousIPs.add("203.0.113.1");
            knownMaliciousIPs.add("192.0.2.1");
        }

        public void analyzeEvent(NetworkEvent event) {
            if (knownMaliciousIPs.contains(event.getSourceIP())) {
                event.addAdditionalData("threat_intel", "Known malicious IP");
            }
        }
    }

    public static class NetworkStatistics {
        private long totalBytesTransferred;
        private long totalConnections;
        private LocalDateTime startTime;

        public NetworkStatistics() {
            this.totalBytesTransferred = 0;
            this.totalConnections = 0;
            this.startTime = LocalDateTime.now();
        }

        public void updateStats(NetworkEvent event) {
            totalBytesTransferred += event.getBytesTransferred();
            totalConnections++;
        }

        public void displayStatistics() {
            System.out.printf("Total Connections: %,d\n", totalConnections);
            System.out.printf("Total Data Transferred: %,d bytes (%.2f MB)\n",
                    totalBytesTransferred, totalBytesTransferred / (1024.0 * 1024.0));
        }

        // GUI getters
        public long getTotalConnections() { return totalConnections; }
        public long getTotalBytesTransferred() { return totalBytesTransferred; }
        public LocalDateTime getStartTime() { return startTime; }
    }
}