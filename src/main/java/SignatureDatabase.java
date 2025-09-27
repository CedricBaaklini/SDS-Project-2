import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class SignatureDatabase {
    private static final Logger logger = Logger.getLogger(SignatureDatabase.class.getName());
    private final Map<String, Signature> signatures = new ConcurrentHashMap<>();
    private final Map<String, ThreatIntelligence> threatIntel = new ConcurrentHashMap<>();

    public void loadSignatures() {
        try {
            loadFromFile();
            loadDefaultSignatures();
            logger.info("Loaded " + signatures.size() + " signatures");
        } catch (Exception e) {
            logger.severe("Failed to load signatures: " + e.getMessage());
        }
    }

    public void loadThreatIntelligence() {
        try {
            loadThreatIntelFromFile();
            logger.info("Loaded threat intelligence for " + threatIntel.size() + " IPs");
        } catch (Exception e) {
            logger.warning("Failed to load threat intelligence: " + e.getMessage());
        }
    }

    public List<Signature> findMatches(PacketInfo packet) {
        List<Signature> matches = new ArrayList<>();

        // Check IP-based signatures
        String sourceIP = packet.sourceIP();
        if (threatIntel.containsKey(sourceIP)) {
            ThreatIntelligence intel = threatIntel.get(sourceIP);
            matches.add(new Signature(
                    "THREAT_IP_" + sourceIP,
                    "Known malicious IP",
                    intel.severity(),
                    sourceIP
            ));
        }

        // Check port-based signatures
        int destPort = packet.destinationPort();
        if (isKnownMaliciousPort(destPort)) {
            matches.add(new Signature("MALICIOUS_PORT_" + destPort, "Access to known malicious port", Severity.HIGH, String.valueOf(destPort)
            ));
        }

        return matches;
    }

    public void updateSignatures() {
        logger.info("Updating signatures from threat feeds...");
    }

    public void updateThreatIntelligence(String ip, ThreatType threatType) {
        threatIntel.put(ip, new ThreatIntelligence(ip, threatType, Severity.MEDIUM));
        logger.info("Updated threat intelligence for IP: " + ip);
    }

    private void loadFromFile() {
        try (BufferedReader reader = new BufferedReader(new FileReader("signatures.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    String[] parts = line.split(",");
                    if (parts.length >= 3) {
                        signatures.put(parts[0], new Signature(parts[0], parts[1], Severity.valueOf(parts[2].toUpperCase()), parts.length > 3 ? parts[3] : ""));
                    }
                }
            }
        } catch (FileNotFoundException e) {
            logger.info("Signatures file not found, using defaults only");
        } catch (IOException e) {
            logger.severe("Error reading signatures file: " + e.getMessage());
        }
    }

    private void loadThreatIntelFromFile() {
        // Load from ips.txt as threat intelligence
        try (BufferedReader reader = new BufferedReader(new FileReader("ips.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    threatIntel.put(line, new ThreatIntelligence(
                            line, ThreatType.SUSPICIOUS_IP, Severity.MEDIUM
                    ));
                }
            }
        } catch (IOException e) {
            logger.warning("Could not load threat intelligence: " + e.getMessage());
        }
    }

    private void loadDefaultSignatures() {
        // Load default attack signatures
        signatures.put("PORT_SCAN", new Signature(
                "PORT_SCAN", "Multiple port access pattern", Severity.HIGH, "scan"
        ));
        signatures.put("DDOS", new Signature(
                "DDOS", "High volume traffic pattern", Severity.CRITICAL, "flood"
        ));
        signatures.put("BRUTE_FORCE", new Signature(
                "BRUTE_FORCE", "Multiple failed login attempts", Severity.HIGH, "brute"
        ));
    }

    private boolean isKnownMaliciousPort(int port) {
        int[] maliciousPorts = {135, 139, 445, 1433, 1434, 4444, 5554, 9999};
        return Arrays.stream(maliciousPorts).anyMatch(p -> p == port);
    }
}