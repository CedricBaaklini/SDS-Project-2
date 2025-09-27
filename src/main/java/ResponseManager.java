import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class ResponseManager {
    private static final Logger logger = Logger.getLogger(ResponseManager.class.getName());
    private final Map<String, BlockedIP> blockedIPs = new ConcurrentHashMap<>();
    private final Map<String, RateLimit> rateLimitedIPs = new ConcurrentHashMap<>();
    private final Set<String> quarantinedIPs = ConcurrentHashMap.newKeySet();

    public void initializeFirewallIntegration() {
        logger.info("Initializing firewall integration...");
        // In real implementation, this would connect to iptables, pfSense, etc.
    }

    public ResponseAction determineAction(ThreatDetection detection) {
        Severity severity = detection.severity();
        ThreatType threatType = detection.threatType();

        switch (severity) {
            case CRITICAL:
                if (threatType == ThreatType.DDOS_ATTACK) {
                    return new ResponseAction(ActionType.BLOCK_IP, 3600000, 0); // 1 hour block
                } else {
                    return new ResponseAction(ActionType.QUARANTINE, 1800000, 0); // 30 min quarantine
                }

            case HIGH:
                if (threatType == ThreatType.PORT_SCAN) {
                    return new ResponseAction(ActionType.BLOCK_IP, 1800000, 0); // 30 min block
                } else {
                    return new ResponseAction(ActionType.RATE_LIMIT, 0, 10); // 10 packets/sec
                }

            case MEDIUM:
                return new ResponseAction(ActionType.RATE_LIMIT, 0, 50); // 50 packets/sec

            case LOW:
            default:
                return new ResponseAction(ActionType.ALERT_ONLY, 0, 0);
        }
    }

    public void blockIP(String ip, long durationMs) {
        BlockedIP blockedIP = new BlockedIP(ip, System.currentTimeMillis() + durationMs);
        blockedIPs.put(ip, blockedIP);

        // Execute actual blocking (would integrate with firewall)
        executeFirewallRule("block", ip);

        logger.info("Blocked IP: " + ip + " for " + (durationMs/1000) + " seconds");
    }

    public void rateLimitIP(String ip, int packetsPerSecond) {
        RateLimit rateLimit = new RateLimit(ip, packetsPerSecond, System.currentTimeMillis());
        rateLimitedIPs.put(ip, rateLimit);

        // Execute rate limiting (would integrate with traffic shaping)
        executeRateLimitRule(ip, packetsPerSecond);

        logger.info("Rate limited IP: " + ip + " to " + packetsPerSecond + " packets/sec");
    }

    public void quarantineIP(String ip) {
        quarantinedIPs.add(ip);

        // Move to quarantine network segment
        executeQuarantineRule(ip);

        logger.info("Quarantined IP: " + ip);
    }

    public boolean isBlocked(String ip) {
        BlockedIP blocked = blockedIPs.get(ip);
        if (blocked != null && System.currentTimeMillis() > blocked.expiryTime()) {
            // Block expired, remove it
            unblockIP(ip);
            return false;
        }
        return blocked != null;
    }

    public boolean isRateLimited(String ip) {
        return rateLimitedIPs.containsKey(ip);
    }

    public boolean isQuarantined(String ip) {
        return quarantinedIPs.contains(ip);
    }

    public void cleanupExpiredBlocks() {
        long currentTime = System.currentTimeMillis();

        // Remove expired IP blocks
        blockedIPs.entrySet().removeIf(entry -> {
            if (currentTime > entry.getValue().expiryTime()) {
                unblockIP(entry.getKey());
                return true;
            }
            return false;
        });

        // Remove old rate limits (after 1 hour)
        rateLimitedIPs.entrySet().removeIf(entry -> {
            if (currentTime - entry.getValue().createdTime() > 3600000) {
                removeRateLimit(entry.getKey());
                return true;
            }
            return false;
        });
    }

    private void unblockIP(String ip) {
        executeFirewallRule("unblock", ip);
        logger.info("Unblocked IP: " + ip);
    }

    private void removeRateLimit(String ip) {
        executeRateLimitRule(ip, -1); // Remove rate limit
        logger.info("Removed rate limit for IP: " + ip);
    }

    private void executeFirewallRule(String action, String ip) {
        // In real implementation, this would execute iptables commands or API calls
        logger.fine("Firewall rule: " + action + " " + ip);
    }

    private void executeRateLimitRule(String ip, int packetsPerSecond) {
        // In real implementation, this would configure traffic shaping
        logger.fine("Rate limit rule: " + ip + " -> " + packetsPerSecond + " pps");
    }

    private void executeQuarantineRule(String ip) {
        // In real implementation, this would move IP to quarantine VLAN
        logger.fine("Quarantine rule: " + ip);
    }

    public Map<String, String> getActiveBlocks() {
        Map<String, String> active = new HashMap<>();
        long currentTime = System.currentTimeMillis();

        blockedIPs.forEach((ip, blocked) -> {
            long remainingTime = (blocked.expiryTime() - currentTime) / 1000;
            if (remainingTime > 0) {
                active.put(ip, remainingTime + "s remaining");
            }
        });

        return active;
    }

    private record BlockedIP(String ip, long expiryTime) {
    }

    private record RateLimit(String ip, int packetsPerSecond, long createdTime) {
    }
}