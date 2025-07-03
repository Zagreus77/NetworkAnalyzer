import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

public class NetworkAnalyzerGUI extends JFrame {
    private NetworkAnalyzer analyzer;
    private JLabel statusLabel;
    private JLabel totalEventsLabel;
    private JLabel suspiciousEventsLabel;
    private JLabel criticalEventsLabel;
    private JLabel riskLevelLabel;
    private JButton monitoringButton;
    private JTable eventsTable;
    private JTable alertsTable;
    private DefaultTableModel eventsTableModel;
    private DefaultTableModel alertsTableModel;
    private JTextArea logTextArea;
    private JProgressBar riskProgressBar;
    private Timer refreshTimer;

    // Modern dark theme colors
    private final Color DARK_PRIMARY = new Color(26, 32, 46);
    private final Color DARK_SECONDARY = new Color(35, 45, 65);
    private final Color DARK_ACCENT = new Color(45, 55, 75);
    private final Color SURFACE_COLOR = new Color(55, 65, 85);
    private final Color TEXT_PRIMARY = new Color(59, 130, 246);  // Blue text
    private final Color TEXT_SECONDARY = new Color(34, 197, 94);  // Green text

    // Status colors - modern palette
    private final Color CRITICAL_COLOR = new Color(248, 113, 113);
    private final Color HIGH_COLOR = new Color(251, 191, 36);
    private final Color MEDIUM_COLOR = new Color(139, 92, 246);
    private final Color LOW_COLOR = new Color(34, 197, 94);
    private final Color NORMAL_COLOR = new Color(100, 116, 139);

    // Accent colors
    private final Color ACCENT_BLUE = new Color(59, 130, 246);
    private final Color ACCENT_PURPLE = new Color(147, 51, 234);
    private final Color ACCENT_GREEN = new Color(16, 185, 129);

    public NetworkAnalyzerGUI() {
        this.analyzer = new NetworkAnalyzer();
        initializeGUI();
        setupCallbacks();
        startRefreshTimer();
    }

    private void initializeGUI() {
        setTitle("SOC Network Security Analyzer - Professional Dashboard");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Apply modern look and feel
        applyModernTheme();

        // Create main panels
        createTopPanel();
        createCenterPanel();
        createBottomPanel();

        // Set window properties
        setSize(1400, 900);
        setLocationRelativeTo(null);
        setExtendedState(JFrame.MAXIMIZED_BOTH);

        // Set background
        getContentPane().setBackground(DARK_PRIMARY);

        // Update initial data
        updateDashboard();
    }

    private void applyModernTheme() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

            // Customize UI defaults for modern look
            UIManager.put("Panel.background", DARK_SECONDARY);
            UIManager.put("OptionPane.background", DARK_SECONDARY);
            UIManager.put("TabbedPane.background", DARK_SECONDARY);
            UIManager.put("TabbedPane.foreground", ACCENT_BLUE);
            UIManager.put("TabbedPane.selected", DARK_ACCENT);
            UIManager.put("TabbedPane.selectedForeground", ACCENT_GREEN);
            UIManager.put("Table.background", SURFACE_COLOR);
            UIManager.put("Table.foreground", TEXT_PRIMARY);
            UIManager.put("Table.gridColor", DARK_ACCENT);
            UIManager.put("TableHeader.background", DARK_ACCENT);
            UIManager.put("TableHeader.foreground", TEXT_PRIMARY);
            UIManager.put("ScrollPane.background", DARK_SECONDARY);
            UIManager.put("Viewport.background", DARK_SECONDARY);
            UIManager.put("TextArea.background", DARK_ACCENT);
            UIManager.put("TextArea.foreground", TEXT_PRIMARY);
            UIManager.put("TextArea.caretForeground", TEXT_PRIMARY);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBackground(DARK_PRIMARY);
        topPanel.setBorder(BorderFactory.createEmptyBorder(20, 30, 20, 30));

        // Modern title with gradient effect
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        titlePanel.setOpaque(false);

        JLabel titleLabel = new JLabel("🛡️ SOC Network Security Analyzer");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 28));
        titleLabel.setForeground(ACCENT_BLUE);

        JLabel subtitleLabel = new JLabel("Real-time Network Threat Detection & Analysis");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        subtitleLabel.setForeground(ACCENT_GREEN);

        JPanel titleContainer = new JPanel(new BorderLayout());
        titleContainer.setOpaque(false);
        titleContainer.add(titleLabel, BorderLayout.NORTH);
        titleContainer.add(subtitleLabel, BorderLayout.SOUTH);

        // Status info with modern styling
        JPanel statusPanel = createStatusPanel();

        topPanel.add(titleContainer, BorderLayout.WEST);
        topPanel.add(statusPanel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);
    }

    private JPanel createStatusPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 15, 0));
        panel.setOpaque(false);

        // Status indicator with modern design
        JPanel statusContainer = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
        statusContainer.setOpaque(false);

        JLabel statusIcon = new JLabel("●");
        statusIcon.setFont(new Font("Arial", Font.BOLD, 16));
        statusIcon.setForeground(LOW_COLOR);

        statusLabel = new JLabel("System Ready");
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        statusLabel.setForeground(ACCENT_GREEN);

        statusContainer.add(statusIcon);
        statusContainer.add(statusLabel);

        // Modern button design
        monitoringButton = createModernButton("Start Monitoring", ACCENT_GREEN);
        monitoringButton.addActionListener(e -> toggleMonitoring());

        panel.add(statusContainer);
        panel.add(monitoringButton);

        return panel;
    }

    private JButton createModernButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setFont(new Font("Segoe UI", Font.BOLD, 12));
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setPreferredSize(new Dimension(140, 40));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));

        // Add hover effect
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(brightenColor(bgColor, 20));
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(bgColor);
            }
        });

        return button;
    }

    private Color brightenColor(Color color, int amount) {
        int r = Math.min(255, color.getRed() + amount);
        int g = Math.min(255, color.getGreen() + amount);
        int b = Math.min(255, color.getBlue() + amount);
        return new Color(r, g, b);
    }

    private void createCenterPanel() {
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBackground(DARK_PRIMARY);

        // Create modern tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("Segoe UI", Font.BOLD, 13));
        tabbedPane.setBackground(DARK_SECONDARY);
        tabbedPane.setForeground(ACCENT_BLUE);
        tabbedPane.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));

        // Style the selected tab
        tabbedPane.addChangeListener(e -> {
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                if (i == tabbedPane.getSelectedIndex()) {
                    tabbedPane.setForegroundAt(i, ACCENT_GREEN);
                } else {
                    tabbedPane.setForegroundAt(i, ACCENT_BLUE);
                }
            }
        });

        // Dashboard tab
        tabbedPane.addTab("🎯 Dashboard", createDashboardPanel());

        // Events tab
        tabbedPane.addTab("📊 Network Events", createEventsPanel());

        // Alerts tab
        tabbedPane.addTab("🚨 Security Alerts", createAlertsPanel());

        // Statistics tab
        tabbedPane.addTab("📈 Statistics", createStatisticsPanel());

        centerPanel.add(tabbedPane, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);
    }

    private JPanel createDashboardPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 3, 20, 20));
        panel.setBackground(DARK_PRIMARY);
        panel.setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));

        // Create modern cards
        panel.add(createStatusCard());
        panel.add(createTotalEventsCard());
        panel.add(createSuspiciousEventsCard());
        panel.add(createCriticalEventsCard());
        panel.add(createRiskLevelCard());
        panel.add(createActiveAlertsCard());

        return panel;
    }

    private JPanel createStatusCard() {
        JPanel card = createModernCard("🛡️ System Status", ACCENT_BLUE);

        JLabel statusText = new JLabel("OPERATIONAL", SwingConstants.CENTER);
        statusText.setFont(new Font("Segoe UI", Font.BOLD, 20));
        statusText.setForeground(Color.WHITE);

        card.add(statusText, BorderLayout.CENTER);
        return card;
    }

    private JPanel createTotalEventsCard() {
        JPanel card = createModernCard("📊 Total Events", ACCENT_BLUE);

        totalEventsLabel = new JLabel("0", SwingConstants.CENTER);
        totalEventsLabel.setFont(new Font("Segoe UI", Font.BOLD, 36));
        totalEventsLabel.setForeground(Color.WHITE);

        card.add(totalEventsLabel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createSuspiciousEventsCard() {
        JPanel card = createModernCard("⚠️ Suspicious Events", HIGH_COLOR);

        suspiciousEventsLabel = new JLabel("0", SwingConstants.CENTER);
        suspiciousEventsLabel.setFont(new Font("Segoe UI", Font.BOLD, 36));
        suspiciousEventsLabel.setForeground(Color.WHITE);

        card.add(suspiciousEventsLabel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createCriticalEventsCard() {
        JPanel card = createModernCard("🚨 Critical Events", CRITICAL_COLOR);

        criticalEventsLabel = new JLabel("0", SwingConstants.CENTER);
        criticalEventsLabel.setFont(new Font("Segoe UI", Font.BOLD, 36));
        criticalEventsLabel.setForeground(Color.WHITE);

        card.add(criticalEventsLabel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createRiskLevelCard() {
        JPanel card = createModernCard("🎯 Risk Level", ACCENT_PURPLE);

        JPanel riskPanel = new JPanel(new BorderLayout(0, 10));
        riskPanel.setOpaque(false);

        riskLevelLabel = new JLabel("LOW", SwingConstants.CENTER);
        riskLevelLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        riskLevelLabel.setForeground(Color.WHITE);

        riskProgressBar = new JProgressBar(0, 100);
        riskProgressBar.setValue(20);
        riskProgressBar.setStringPainted(true);
        riskProgressBar.setString("20%");
        riskProgressBar.setBackground(new Color(255, 255, 255, 50));
        riskProgressBar.setForeground(Color.WHITE);
        riskProgressBar.setFont(new Font("Segoe UI", Font.BOLD, 12));

        riskPanel.add(riskLevelLabel, BorderLayout.CENTER);
        riskPanel.add(riskProgressBar, BorderLayout.SOUTH);

        card.add(riskPanel, BorderLayout.CENTER);
        return card;
    }

    private JPanel createActiveAlertsCard() {
        JPanel card = createModernCard("🔔 Active Alerts", ACCENT_PURPLE);

        JLabel alertsCount = new JLabel("0", SwingConstants.CENTER);
        alertsCount.setFont(new Font("Segoe UI", Font.BOLD, 36));
        alertsCount.setForeground(Color.WHITE);

        card.add(alertsCount, BorderLayout.CENTER);
        return card;
    }

    private JPanel createModernCard(String title, Color color) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(color);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(255, 255, 255, 30), 1),
                BorderFactory.createEmptyBorder(20, 20, 20, 20)
        ));

        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setForeground(ACCENT_BLUE);

        card.add(titleLabel, BorderLayout.NORTH);
        return card;
    }

    private JPanel createEventsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(DARK_SECONDARY);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Create modern events table
        String[] eventColumns = {"Timestamp", "Source IP", "Dest IP", "Event Type", "Severity", "Description"};
        eventsTableModel = new DefaultTableModel(eventColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        eventsTable = new JTable(eventsTableModel);
        styleModernTable(eventsTable);
        eventsTable.getColumnModel().getColumn(4).setCellRenderer(new ModernSeverityCellRenderer());

        JScrollPane eventsScrollPane = new JScrollPane(eventsTable);
        styleModernScrollPane(eventsScrollPane, "Network Events Log");

        // Modern control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.setBackground(DARK_SECONDARY);

        JButton clearEventsButton = createModernButton("Clear Events", CRITICAL_COLOR);
        clearEventsButton.addActionListener(e -> clearEventsTable());
        controlPanel.add(clearEventsButton);

        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(eventsScrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createAlertsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(DARK_SECONDARY);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Create modern alerts table
        String[] alertColumns = {"Alert ID", "Timestamp", "Type", "Severity", "Source IP", "Description"};
        alertsTableModel = new DefaultTableModel(alertColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        alertsTable = new JTable(alertsTableModel);
        styleModernTable(alertsTable);
        alertsTable.getColumnModel().getColumn(3).setCellRenderer(new ModernSeverityCellRenderer());

        JScrollPane alertsScrollPane = new JScrollPane(alertsTable);
        styleModernScrollPane(alertsScrollPane, "Security Alerts");

        // Modern control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.setBackground(DARK_SECONDARY);

        JButton clearAlertsButton = createModernButton("Clear Alerts", CRITICAL_COLOR);
        clearAlertsButton.addActionListener(e -> clearAlertsTable());
        controlPanel.add(clearAlertsButton);

        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(alertsScrollPane, BorderLayout.CENTER);

        return panel;
    }

    private void styleModernTable(JTable table) {
        table.setBackground(SURFACE_COLOR);
        table.setForeground(ACCENT_BLUE);
        table.setSelectionBackground(DARK_ACCENT);
        table.setSelectionForeground(ACCENT_GREEN);
        table.setGridColor(DARK_ACCENT);
        table.setRowHeight(35);
        table.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getTableHeader().setReorderingAllowed(false);

        // Style table header
        JTableHeader header = table.getTableHeader();
        header.setBackground(DARK_ACCENT);
        header.setForeground(ACCENT_BLUE);
        header.setFont(new Font("Segoe UI", Font.BOLD, 12));
        header.setPreferredSize(new Dimension(0, 40));
    }

    private void styleModernScrollPane(JScrollPane scrollPane, String title) {
        scrollPane.setBackground(DARK_SECONDARY);
        scrollPane.getViewport().setBackground(SURFACE_COLOR);
        scrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(DARK_ACCENT, 1),
                title,
                TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION,
                new Font("Segoe UI", Font.BOLD, 14),
                ACCENT_BLUE
        ));
    }

    private JPanel createStatisticsPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2, 20, 20));
        panel.setBackground(DARK_SECONDARY);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Threat types chart
        JPanel threatPanel = new JPanel(new BorderLayout());
        threatPanel.setBackground(DARK_SECONDARY);
        threatPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(DARK_ACCENT, 1),
                "Threat Distribution",
                TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION,
                new Font("Segoe UI", Font.BOLD, 14),
                ACCENT_BLUE
        ));

        JTextArea threatStats = new JTextArea();
        threatStats.setEditable(false);
        threatStats.setFont(new Font("JetBrains Mono", Font.PLAIN, 12));
        threatStats.setBackground(SURFACE_COLOR);
        threatStats.setForeground(ACCENT_GREEN);
        threatStats.setCaretColor(ACCENT_GREEN);

        JScrollPane threatScrollPane = new JScrollPane(threatStats);
        threatScrollPane.setBackground(DARK_SECONDARY);
        threatScrollPane.getViewport().setBackground(SURFACE_COLOR);
        threatPanel.add(threatScrollPane, BorderLayout.CENTER);

        // Network statistics
        JPanel networkPanel = new JPanel(new BorderLayout());
        networkPanel.setBackground(DARK_SECONDARY);
        networkPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(DARK_ACCENT, 1),
                "Network Statistics",
                TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION,
                new Font("Segoe UI", Font.BOLD, 14),
                ACCENT_BLUE
        ));

        JTextArea networkStats = new JTextArea();
        networkStats.setEditable(false);
        networkStats.setFont(new Font("JetBrains Mono", Font.PLAIN, 12));
        networkStats.setBackground(SURFACE_COLOR);
        networkStats.setForeground(ACCENT_GREEN);
        networkStats.setCaretColor(ACCENT_GREEN);

        JScrollPane networkScrollPane = new JScrollPane(networkStats);
        networkScrollPane.setBackground(DARK_SECONDARY);
        networkScrollPane.getViewport().setBackground(SURFACE_COLOR);
        networkPanel.add(networkScrollPane, BorderLayout.CENTER);

        panel.add(threatPanel);
        panel.add(networkPanel);

        return panel;
    }

    private void createBottomPanel() {
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBackground(DARK_SECONDARY);
        bottomPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(DARK_ACCENT, 1),
                "System Log",
                TitledBorder.DEFAULT_JUSTIFICATION,
                TitledBorder.DEFAULT_POSITION,
                new Font("Segoe UI", Font.BOLD, 14),
                ACCENT_BLUE
        ));
        bottomPanel.setPreferredSize(new Dimension(0, 180));

        logTextArea = new JTextArea();
        logTextArea.setEditable(false);
        logTextArea.setFont(new Font("JetBrains Mono", Font.PLAIN, 11));
        logTextArea.setBackground(SURFACE_COLOR);
        logTextArea.setForeground(ACCENT_GREEN);
        logTextArea.setCaretColor(ACCENT_GREEN);

        JScrollPane logScrollPane = new JScrollPane(logTextArea);
        logScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        logScrollPane.setBackground(DARK_SECONDARY);
        logScrollPane.getViewport().setBackground(SURFACE_COLOR);

        bottomPanel.add(logScrollPane, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void setupCallbacks() {
        // Set up event callback
        analyzer.setEventCallback(event -> {
            SwingUtilities.invokeLater(() -> {
                addEventToTable(event);
                if (event.isSuspicious()) {
                    logMessage("⚠️ Suspicious event detected: " + event.getEventType() +
                            " from " + event.getSourceIP());
                }
            });
        });

        // Set up alert callback
        analyzer.getAlertManager().setAlertCallback(alert -> {
            SwingUtilities.invokeLater(() -> {
                addAlertToTable(alert);
                logMessage("🚨 ALERT: " + alert.getAlertType() + " - " + alert.getDescription());
            });
        });
    }

    private void toggleMonitoring() {
        if (analyzer.isMonitoring()) {
            analyzer.stopNetworkMonitoring();
            monitoringButton.setText("Start Monitoring");
            monitoringButton.setBackground(ACCENT_GREEN);
            statusLabel.setText("Monitoring Stopped");
            statusLabel.setForeground(ACCENT_BLUE);
            logMessage("🛑 Network monitoring stopped");
        } else {
            analyzer.startNetworkMonitoring();
            monitoringButton.setText("Stop Monitoring");
            monitoringButton.setBackground(CRITICAL_COLOR);
            statusLabel.setText("Monitoring Active");
            statusLabel.setForeground(ACCENT_GREEN);
            logMessage("🔍 Network monitoring started");
        }
    }

    private void startRefreshTimer() {
        refreshTimer = new Timer(2000, e -> updateDashboard());
        refreshTimer.start();
    }

    private void updateDashboard() {
        long totalEvents = analyzer.getEvents().size();
        long suspiciousEvents = analyzer.getSuspiciousEventCount();
        long criticalEvents = analyzer.getCriticalEventCount();
        String riskLevel = analyzer.getSecurityStatus();

        totalEventsLabel.setText(String.valueOf(totalEvents));
        suspiciousEventsLabel.setText(String.valueOf(suspiciousEvents));
        criticalEventsLabel.setText(String.valueOf(criticalEvents));
        riskLevelLabel.setText(riskLevel);

        // Update risk progress bar
        int riskValue = calculateRiskValue(riskLevel);
        riskProgressBar.setValue(riskValue);
        riskProgressBar.setString(riskValue + "%");
    }

    private int calculateRiskValue(String riskLevel) {
        switch (riskLevel) {
            case "CRITICAL": return 90;
            case "HIGH": return 70;
            case "MEDIUM": return 50;
            case "LOW": return 20;
            default: return 10;
        }
    }

    private void addEventToTable(NetworkEvent event) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        Object[] rowData = {
                event.getTimestamp().format(formatter),
                event.getSourceIP(),
                event.getDestinationIP(),
                event.getEventType(),
                event.getSeverity(),
                event.getDescription()
        };

        eventsTableModel.insertRow(0, rowData);

        // Keep only last 100 events in table
        if (eventsTableModel.getRowCount() > 100) {
            eventsTableModel.removeRow(eventsTableModel.getRowCount() - 1);
        }
    }

    private void addAlertToTable(AlertManager.Alert alert) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        Object[] rowData = {
                alert.getId(),
                alert.getTimestamp().format(formatter),
                alert.getAlertType(),
                alert.getSeverity(),
                alert.getSourceIP(),
                alert.getDescription()
        };

        alertsTableModel.insertRow(0, rowData);

        // Keep only last 50 alerts in table
        if (alertsTableModel.getRowCount() > 50) {
            alertsTableModel.removeRow(alertsTableModel.getRowCount() - 1);
        }
    }

    private void clearEventsTable() {
        eventsTableModel.setRowCount(0);
        logMessage("📋 Events table cleared");
    }

    private void clearAlertsTable() {
        alertsTableModel.setRowCount(0);
        logMessage("🗑️ Alerts table cleared");
    }

    private void logMessage(String message) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        String timestamp = java.time.LocalDateTime.now().format(formatter);
        logTextArea.append("[" + timestamp + "] " + message + "\n");
        logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
    }

    // Modern cell renderer for severity colors
    private class ModernSeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {

            Component component = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);

            if (!isSelected && value != null) {
                String severity = value.toString();
                setHorizontalAlignment(SwingConstants.CENTER);
                setFont(new Font("Segoe UI", Font.BOLD, 11));

                switch (severity) {
                    case "CRITICAL":
                        setBackground(CRITICAL_COLOR);
                        setForeground(Color.WHITE);
                        break;
                    case "HIGH":
                        setBackground(HIGH_COLOR);
                        setForeground(Color.WHITE);
                        break;
                    case "MEDIUM":
                        setBackground(MEDIUM_COLOR);
                        setForeground(Color.WHITE);
                        break;
                    case "LOW":
                        setBackground(LOW_COLOR);
                        setForeground(Color.WHITE);
                        break;
                    default:
                        setBackground(table.getBackground());
                        setForeground(table.getForeground());
                }
            } else if (isSelected) {
                setBackground(table.getSelectionBackground());
                setForeground(table.getSelectionForeground());
            }

            return component;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new NetworkAnalyzerGUI().setVisible(true);
        });
    }
}