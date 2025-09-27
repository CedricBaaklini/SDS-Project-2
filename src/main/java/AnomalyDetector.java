import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class AnomalyDetector {
    private static final Logger logger = Logger.getLogger(AnomalyDetector.class.getName());
    // Configuration
    private static final double ANOMALY_THRESHOLD = 2.0; // Standard deviations
    private static final int BASELINE_WINDOW = 1000; // Number of packets for baseline
    // Baseline tracking
    private final Map<String, TrafficBaseline> ipBaselines = new ConcurrentHashMap<>();
    private final Map<Integer, PortBaseline> portBaselines = new ConcurrentHashMap<>();
    private final Map<Integer, ProtocolBaseline> protocolBaselines = new ConcurrentHashMap<>();

    public boolean isAnomalous(PacketInfo packet) {
        return isTrafficVolumeAnomaly(packet) || isPortAccessAnomaly(packet) || isProtocolAnomaly(packet) || isTimingAnomaly(packet);
    }

    public void updateBaseline(PacketInfo packet) {
        updateTrafficBaseline(packet);
        updatePortBaseline(packet);
        updateProtocolBaseline(packet);
    }

    private boolean isTrafficVolumeAnomaly(PacketInfo packet) {
        String sourceIP = packet.sourceIP();
        TrafficBaseline baseline = ipBaselines.get(sourceIP);

        if (baseline == null || baseline.getSampleCount() < 100) {
            return false; 
        }

        double currentRate = calculateCurrentRate(sourceIP);
        double avgRate = baseline.getAverageRate();
        double stdDev = baseline.getStandardDeviation();

        if (stdDev == 0) {
            return false;
        }

        double zScore = Math.abs(currentRate - avgRate) / stdDev;
        return zScore > ANOMALY_THRESHOLD;
    }

    private boolean isPortAccessAnomaly(PacketInfo packet) {
        int port = packet.destinationPort();
        PortBaseline baseline = portBaselines.get(port);

        if (baseline == null) {
            return port > 49152; // High ports are potentially anomalous
        }

        // Check if this is an unusual time for accessing this port
        long currentHour = (packet.timestamp() / (1000 * 60 * 60)) % 24;
        return !baseline.isNormalAccessTime(currentHour);
    }

    private boolean isProtocolAnomaly(PacketInfo packet) {
        int protocol = packet.protocol();
        ProtocolBaseline baseline = protocolBaselines.get(protocol);

        // Uncommon protocols are potentially anomalous
        if (protocol != 1 && protocol != 6 && protocol != 17) { // Not ICMP, TCP, UDP
            return true;
        }

        if (baseline == null) return false;

        // Check if packet size is anomalous for this protocol
        double avgSize = baseline.getAveragePacketSize();
        double stdDev = baseline.getPacketSizeStdDev();

        if (stdDev == 0) return false;

        double zScore = Math.abs(packet.packetSize() - avgSize) / stdDev;
        return zScore > ANOMALY_THRESHOLD;
    }

    private boolean isTimingAnomaly(PacketInfo packet) {
        // Check for unusual timing patterns (e.g., regular intervals suggesting automation)
        String sourceIP = packet.sourceIP();
        TrafficBaseline baseline = ipBaselines.get(sourceIP);

        if (baseline == null) return false;

        return baseline.hasRegularTimingPattern();
    }

    private void updateTrafficBaseline(PacketInfo packet) {
        String sourceIP = packet.sourceIP();
        ipBaselines.computeIfAbsent(sourceIP, k -> new TrafficBaseline())
                .addPacket(packet);
    }

    private void updatePortBaseline(PacketInfo packet) {
        int port = packet.destinationPort();
        portBaselines.computeIfAbsent(port, k -> new PortBaseline()).addAccess(packet.timestamp());
    }

    private void updateProtocolBaseline(PacketInfo packet) {
        int protocol = packet.protocol();
        protocolBaselines.computeIfAbsent(protocol, k -> new ProtocolBaseline())
                .addPacket(packet.packetSize());
    }

    private double calculateCurrentRate(String sourceIP) {
        TrafficBaseline baseline = ipBaselines.get(sourceIP);
        return baseline != null ? baseline.getCurrentRate() : 0.0;
    }

    private static class TrafficBaseline {
        private final List<Long> timestamps = new ArrayList<>();
        private final List<Integer> packetSizes = new ArrayList<>();
        private double averageRate = 0.0;
        private double standardDeviation = 0.0;

        void addPacket(PacketInfo packet) {
            timestamps.add(packet.timestamp());
            packetSizes.add(packet.packetSize());

            // Keep only recent data
            long cutoff = packet.timestamp() - 60000; 
            timestamps.removeIf(t -> t < cutoff);

            if (timestamps.size() > BASELINE_WINDOW) {
                timestamps.removeFirst();
                packetSizes.removeFirst();
            }

            updateStatistics();
        }

        private void updateStatistics() {
            if (timestamps.size() < 2) return;

            // Calculate rate (packets per second)
            long timeSpan = timestamps.getLast() - timestamps.getFirst();
            averageRate = timeSpan > 0 ? (timestamps.size() * 1000.0 / timeSpan) : 0.0;

            // Calculate standard deviation (simplified)
            double sum = 0.0;
            for (int i = 1; i < timestamps.size(); i++) {
                long interval = timestamps.get(i) - timestamps.get(i - 1);
                sum += interval * interval;
            }
            standardDeviation = Math.sqrt(sum / timestamps.size());
        }

        double getAverageRate() { return averageRate; }
        double getStandardDeviation() { return standardDeviation; }
        int getSampleCount() { return timestamps.size(); }
        double getCurrentRate() { return averageRate; }

        boolean hasRegularTimingPattern() {
            if (timestamps.size() < 10) return false;

            // Check for suspiciously regular intervals
            List<Long> intervals = new ArrayList<>();
            for (int i = 1; i < timestamps.size(); i++) {
                intervals.add(timestamps.get(i) - timestamps.get(i - 1));
            }

            long avgInterval = intervals.stream().mapToLong(Long::longValue).sum() / intervals.size();
            long similarCount = intervals.stream()
                    .mapToLong(interval -> Math.abs(interval - avgInterval) < 100 ? 1 : 0)
                    .sum();

            return similarCount > intervals.size() * 0.8; 
        }
    }

    private static class PortBaseline {
        private final Map<Integer, Integer> hourlyAccess = new HashMap<>();

        void addAccess(long timestamp) {
            int hour = (int) ((timestamp / (1000 * 60 * 60)) % 24);
            hourlyAccess.merge(hour, 1, Integer::sum);
        }

        boolean isNormalAccessTime(long hour) {
            int accesses = hourlyAccess.getOrDefault((int)hour, 0);
            int totalAccesses = hourlyAccess.values().stream().mapToInt(Integer::intValue).sum();

            if (totalAccesses < 10) return true; // Not enough data

            double normalizedAccess = (double) accesses / totalAccesses;
            return normalizedAccess > 0.01; 
        }
    }

    private static class ProtocolBaseline {
        private final List<Integer> packetSizes = new ArrayList<>();
        private double averageSize = 0.0;
        private double stdDev = 0.0;

        void addPacket(int size) {
            packetSizes.add(size);

            if (packetSizes.size() > BASELINE_WINDOW) {
                packetSizes.removeFirst();
            }

            updateStatistics();
        }

        private void updateStatistics() {
            if (packetSizes.isEmpty()) return;

            averageSize = packetSizes.stream().mapToInt(Integer::intValue).average().orElse(0.0);

            double variance = packetSizes.stream()
                    .mapToDouble(size -> Math.pow(size - averageSize, 2))
                    .average().orElse(0.0);
            stdDev = Math.sqrt(variance);
        }

        double getAveragePacketSize() { return averageSize; }
        double getPacketSizeStdDev() { return stdDev; }
    }
}