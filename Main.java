
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        System.out.println("=== SOC Network Analyzer ===");
        System.out.println("Network Security Monitoring Tool");
        System.out.println("Version 2.0\n");

        Scanner scanner = new Scanner(System.in);

        System.out.println("Choose interface:");
        System.out.println("1. GUI (Graphical Interface)");
        System.out.println("2. Terminal (Command Line)");
        System.out.print("Select option (1 or 2): ");

        String choice = scanner.nextLine().trim();

        if (choice.equals("1")) {
            // Launch GUI
            java.awt.EventQueue.invokeLater(() -> {
                new NetworkAnalyzerGUI().setVisible(true);
            });
        } else if (choice.equals("2")) {
            // Launch terminal version
            runTerminalVersion();
        } else {
            System.out.println("Invalid choice. Launching GUI by default...");
            java.awt.EventQueue.invokeLater(() -> {
                new NetworkAnalyzerGUI().setVisible(true);
            });
        }
    }

    private static void runTerminalVersion() {
        NetworkAnalyzer analyzer = new NetworkAnalyzer();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            displayMenu();
            System.out.print("Select option: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    analyzer.startNetworkMonitoring();
                    break;
                case "2":
                    analyzer.analyzeTrafficLogs();
                    break;
                case "3":
                    analyzer.showSecurityDashboard();
                    break;
                case "4":
                    analyzer.generateThreatReport();
                    break;
                case "5":
                    analyzer.configureAlerts();
                    break;
                case "6":
                    analyzer.showStatistics();
                    break;
                case "7":
                    System.out.println("Shutting down Network Analyzer...");
                    return;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
            System.out.println();
        }
    }

    private static void displayMenu() {
        System.out.println("=== SOC Network Analyzer Menu ===");
        System.out.println("1. Start Network Monitoring");
        System.out.println("2. Analyze Traffic Logs");
        System.out.println("3. Security Dashboard");
        System.out.println("4. Generate Threat Report");
        System.out.println("5. Configure Alerts");
        System.out.println("6. Show Statistics");
        System.out.println("7. Exit");
        System.out.println("==================================");
    }
}