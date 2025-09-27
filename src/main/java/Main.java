import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        System.out.println("=== IP-based Intrusion Detection System ===");

        try {
            SimplifiedIPBasedIDS ids = new SimplifiedIPBasedIDS();

            List<String> loadedIPs = loadIPsFromFile("ips.txt");
            System.out.println("Loaded " + loadedIPs.size() + " IPs for monitoring");

            ids.startMonitoring();

            simulateNetworkTraffic(ids, loadedIPs);

            System.out.println("\nIDS is running... Press Enter to stop");
            System.in.read();

            ids.stopMonitoring();

        } catch (Exception e) {
            logger.severe("Error running IDS: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static List<String> loadIPsFromFile(String filename) {
        List<String> ips = new ArrayList<>();

        try (Scanner fileScan = new Scanner(new File(filename))) {
            while (fileScan.hasNextLine()) {
                String line = fileScan.nextLine().trim();

                if (!line.isEmpty() && !line.startsWith("#")) {
                    if (isValidIP(line)) {
                        ips.add(line);
                        System.out.println("Loaded valid IP: " + line);
                    } else {
                        ips.add(line); 
                        System.out.println("Loaded invalid IP (for spoofing tests): " + line);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            logger.severe("Could not find ips.txt file: " + e.getMessage());
            System.out.println("Creating default ips.txt with sample IPs...");
            createDefaultIPFile(filename);
            return loadIPsFromFile(filename); 
        }

        return ips;
    }

    private static void createDefaultIPFile(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("# Sample IPs for IDS testing");
            writer.println("211.175.193.166");
            writer.println("88.182.79.3");
            writer.println("12.16.120.232");
            writer.println("97.77.115.143");
            writer.println("162.242.192.208");
            writer.println("143.170.99.13");
            writer.println("192.168.100.666");  
            writer.println("10.0.0.999");       
            writer.println("172.16.300.50");    
            writer.println("203.0.113.100");
            writer.println("198.51.100.200");
            writer.println("192.0.2.150");
            System.out.println("Created default " + filename);
        } catch (IOException e) {
            logger.severe("Failed to create default IP file: " + e.getMessage());
        }
    }

    private static boolean isValidIP(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;

        try {
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) return false;
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static void simulateNetworkTraffic(SimplifiedIPBasedIDS ids, List<String> fileIPs) {
        System.out.println("\n=== Simulating Network Traffic Using IPs from File ===");

        List<String> validIPs = new ArrayList<>();
        List<String> invalidIPs = new ArrayList<>();

        for (String ip : fileIPs) {
            if (isValidIP(ip)) {
                validIPs.add(ip);
            } else {
                invalidIPs.add(ip);
            }
        }

        System.out.println("Valid IPs available: " + validIPs.size());
        System.out.println("Invalid IPs available: " + invalidIPs.size());

        simulateNormalTraffic(ids, validIPs);
        simulatePortScanAttack(ids, validIPs);
        simulateDDoSAttack(ids, validIPs);
        simulateSuspiciousTraffic(ids, invalidIPs, validIPs);

        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void simulateNormalTraffic(SimplifiedIPBasedIDS ids, List<String> validIPs) {
        if (validIPs.isEmpty()) return;

        System.out.println("\n--- Simulating Normal Traffic from File IPs ---");

        Random random = new Random();
        String[] normalDestIPs = {"8.8.8.8", "1.1.1.1", "208.67.222.222"};
        int[] normalPorts = {80, 443, 53, 25};

        for (int i = 0; i < Math.min(10, validIPs.size() * 2); i++) {
            String sourceIP = validIPs.get(random.nextInt(validIPs.size()));
            String destIP = normalDestIPs[random.nextInt(normalDestIPs.length)];
            int port = normalPorts[random.nextInt(normalPorts.length)];

            SimulatedPacket packet = new SimulatedPacket(sourceIP, destIP, 6, System.currentTimeMillis(), random.nextInt(1400) + 100, port, random.nextInt(65535));

            ids.processPacket(packet);
            System.out.println("Normal traffic: " + sourceIP + " -> " + destIP + ":" + port);
        }
    }

    private static void simulatePortScanAttack(SimplifiedIPBasedIDS ids, List<String> validIPs) {
        if (validIPs.isEmpty()) return;

        System.out.println("\n--- Simulating Port Scan Attack from File IPs ---");

        Random random = new Random();
        String attackerIP = validIPs.getFirst();
        String targetIP = "192.168.1.100";

        System.out.println("Port scan attacker IP from file: " + attackerIP);

        for (int port = 20; port < 35; port++) {
            SimulatedPacket packet = new SimulatedPacket(attackerIP, targetIP, 6, System.currentTimeMillis(), 64, port, 12345);

            ids.processPacket(packet);

            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private static void simulateDDoSAttack(SimplifiedIPBasedIDS ids, List<String> validIPs) {
        if (validIPs.isEmpty()) return;

        System.out.println("\n--- Simulating DDoS Attack from File IPs ---");

        String targetIP = "192.168.1.1";

        List<String> attackerIPs = validIPs.subList(0, Math.min(3, validIPs.size()));
        System.out.println("DDoS attacker IPs from file: " + attackerIPs);

        for (int i = 0; i < 50; i++) {
            for (String attackerIP : attackerIPs) {
                SimulatedPacket packet = new SimulatedPacket(attackerIP, targetIP, 6, System.currentTimeMillis(), 32, 80, 12345 + i);

                ids.processPacket(packet);
            }
        }
    }

    private static void simulateSuspiciousTraffic(SimplifiedIPBasedIDS ids, List<String> invalidIPs, List<String> validIPs) {
        System.out.println("\n--- Simulating Suspicious Traffic from File IPs ---");

        if (!invalidIPs.isEmpty()) {
            for (String spoofedIP : invalidIPs) {
                System.out.println("Testing IP spoofing with: " + spoofedIP);
                SimulatedPacket spoofPacket = new SimulatedPacket(spoofedIP, "8.8.8.8", 6, System.currentTimeMillis(), 1024, 80, 12345);
                
                ids.processPacket(spoofPacket);
            }
        }

        if (!validIPs.isEmpty()) {
            String suspiciousIP = validIPs.getFirst();
            System.out.println("Testing unusual protocol with: " + suspiciousIP);
            SimulatedPacket protocolPacket = new SimulatedPacket(suspiciousIP, "192.168.1.100", 50, System.currentTimeMillis(), 512, 22, 54321);
            ids.processPacket(protocolPacket);
        }

        if (validIPs.size() > 1) {
            String oversizeIP = validIPs.get(1);
            System.out.println("Testing oversized packet with: " + oversizeIP);
            SimulatedPacket oversizedPacket = new SimulatedPacket(oversizeIP, "10.0.0.1", 6, System.currentTimeMillis(), 70000, 443, 12345);
            ids.processPacket(oversizedPacket);
        }

        if (validIPs.size() > 2) {
            String floodIP = validIPs.getLast(); 
            System.out.println("Testing broadcast flood with: " + floodIP);

            for (int i = 0; i < 60; i++) {
                SimulatedPacket broadcastPacket = new SimulatedPacket(floodIP, "255.255.255.255", 17, System.currentTimeMillis(), 128, 137, 12345);
                ids.processPacket(broadcastPacket);
            }
        }
    }
}

class SimplifiedIPBasedIDS {
    private final ExecutorService processingPool;
    private volatile boolean running = false;
    private long totalPackets = 0;
    private long threatsDetected = 0;

    public SimplifiedIPBasedIDS() {
        this.processingPool = Executors.newFixedThreadPool(4);
    }

    public void startMonitoring() {
        running = true;
        System.out.println("IDS started monitoring...");

        Timer timer = new Timer(true);
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                PacketAnalyzer.cleanupOldData();
                printStats();
            }
        }, 5000, 5000); 
    }

    public void stopMonitoring() {
        running = false;
        processingPool.shutdown();
        try {
            if (!processingPool.awaitTermination(5, TimeUnit.SECONDS)) {
                processingPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            processingPool.shutdownNow();
            Thread.currentThread().interrupt();
        }
        System.out.println("IDS stopped monitoring.");
        printFinalStats();
    }

    public void processPacket(SimulatedPacket packet) {
        if (!running) return;

        totalPackets++;

        processingPool.submit(() -> {
            try {
                analyzePacket(packet);
            } catch (Exception e) {
                System.err.println("Error analyzing packet: " + e.getMessage());
            }
        });
    }

    private void analyzePacket(SimulatedPacket packet) {
        PacketAnalyzer analyzer = new PacketAnalyzer(
                packet.sourceIP(),
                packet.destinationIP(),
                packet.protocol(),
                packet.timestamp(),
                packet.packetSize(),
                packet.destinationPort(),
                packet.sourcePort()
        );

        boolean threatDetected = false;

        if (analyzer.isPortScan()) {
            threatDetected = true;
            System.out.println(" THREAT: Port scan detected from " + packet.sourceIP());
        }

        if (analyzer.isDDoSAttack()) {
            threatDetected = true;
            System.out.println(" THREAT: DDoS attack detected from " + packet.sourceIP());
        }

        if (analyzer.isSuspiciousTraffic()) {
            threatDetected = true;
            System.out.println(" THREAT: Suspicious traffic from " + packet.sourceIP());
        }

        if (threatDetected) {
            threatsDetected++;
            logThreatDetails(packet);
        }
    }

    private void logThreatDetails(SimulatedPacket packet) {
        System.out.printf("   Details: %s:%d -> %s:%d (Protocol: %d, Size: %d bytes)%n",
                packet.sourceIP(), packet.sourcePort(),
                packet.destinationIP(), packet.destinationPort(),
                packet.protocol(), packet.packetSize());
    }

    private void printStats() {
        System.out.printf(" Stats: Processed=%d packets, Threats=%d, Detection rate=%.2f%%%n",
                totalPackets, threatsDetected,
                totalPackets > 0 ? (threatsDetected * 100.0 / totalPackets) : 0);
    }

    private void printFinalStats() {
        System.out.println("\n=== Final IDS Statistics ===");
        System.out.println("Total packets processed: " + totalPackets);
        System.out.println("Total threats detected: " + threatsDetected);
        System.out.printf("Detection rate: %.2f%%%n",
                totalPackets > 0 ? (threatsDetected * 100.0 / totalPackets) : 0);
    }
}

record SimulatedPacket(String sourceIP, String destinationIP, int protocol, long timestamp, int packetSize, int destinationPort, int sourcePort) {
    
}
