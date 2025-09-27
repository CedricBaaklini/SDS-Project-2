import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Logger;

public class AlertManager {
    private static final Logger logger = Logger.getLogger(AlertManager.class.getName());
    private final Queue<Alert> activeAlerts = new ConcurrentLinkedQueue<>();
    private final Map<String, Integer> alertCounts = new HashMap<>();
    private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public Alert createAlert(ThreatDetection detection) {
        Alert alert = new Alert(generateAlertId(), detection.threatType(), detection.severity(), detection.description(), detection.packetInfo(), LocalDateTime.now()
        );

        activeAlerts.offer(alert);
        logAlert(alert);
        notifyExternal(alert);
        updateAlertCounts(alert);

        return alert;
    }

    private void logAlert(Alert alert) {
        String logMessage = String.format(
                "[ALERT-%s] %s | %s | %s -> %s | %s",
                alert.id(),
                alert.severity(),
                alert.threatType(),
                alert.packetInfo().sourceIP(),
                alert.packetInfo().destinationIP(),
                alert.description()
        );

        switch (alert.severity()) {
            case CRITICAL:
                logger.severe(logMessage);
                break;
            case HIGH:
                logger.warning(logMessage);
                break;
            case MEDIUM:
            case LOW:
                logger.info(logMessage);
                break;
        }
    }

    private void notifyExternal(Alert alert) {
        // In a real system, this would send notifications via:
        // - Email
        // - SIEM integration
        // - Slack/Teams webhooks
        // - SMS for critical alerts

        if (alert.severity() == Severity.CRITICAL) {
            System.out.println(" CRITICAL ALERT: " + alert.description());
        }
    }

    private void updateAlertCounts(Alert alert) {
        String key = alert.threatType().toString();
        alertCounts.merge(key, 1, Integer::sum);
    }

    private String generateAlertId() {
        return "ALT-" + System.currentTimeMillis() + "-" +
                String.format("%04d", new Random().nextInt(10000));
    }

    public List<Alert> getActiveAlerts() {
        return new ArrayList<>(activeAlerts);
    }

    public Map<String, Integer> getAlertCounts() {
        return new HashMap<>(alertCounts);
    }

    public void clearOldAlerts(long maxAgeMs) {
        LocalDateTime cutoff = LocalDateTime.now().minusNanos(maxAgeMs * 1_000_000);
        activeAlerts.removeIf(alert -> alert.timestamp().isBefore(cutoff));
    }
}