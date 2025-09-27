import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

public class IDS {
    private static final Logger logger = Logger.getLogger(IDS.class.getName());
    private static final int PACKET_QUEUE_SIZE = 10000;
    private static final int PROCESSOR_THREADS = Runtime.getRuntime().availableProcessors();
    private static final long MAINTENANCE_INTERVAL = 300;
    private static final long STATS_REPORT_INTERVAL = 60;
    private final ExecutorService packetProcessingPool;
    private final ScheduledExecutorService maintenanceScheduler;
    private final BlockingQueue<RawPacket> packetQueue;
    private final AtomicBoolean isRunning;
    //This class relies on objects from these classes that I've created for this project.
    private final PacketCapture packetCapture;
    private final SignatureDatabase signatures;
    private final AnomalyDetector anomalyDetector;
    private final AlertManager alertManager;
    private final ResponseManager responseManager;
    private final ConfigurationManager config;
    private volatile long totalPacketsProcessed = 0;
    private volatile long threatsDetected = 0;
    private final long falsePositives = 0;

    public IDS() {
        this.alertManager = new AlertManager();
        this.anomalyDetector = new AnomalyDetector();
        this.config = new ConfigurationManager();
        this.packetCapture = new PacketCapture();
        this.responseManager = new ResponseManager();
        this.signatures = new SignatureDatabase();

        this.packetProcessingPool = Executors.newFixedThreadPool(PROCESSOR_THREADS);
        this.maintenanceScheduler = Executors.newScheduledThreadPool(2);
        this.packetQueue = new ArrayBlockingQueue<>(PACKET_QUEUE_SIZE);
        this.isRunning = new AtomicBoolean(false);

        initializeComponents();
        scheduleMaintenanceTasks();
    }

    public void startMonitoring() {
        if (isRunning.compareAndSet(false, true)) {
            logger.info("Starting IDS monitoring...");

            loadConfiguration();
            signatures.loadSignatures();

            startPacketProcessors();

            packetCapture.startCapture(this::onPacketReceived);

            logger.info("Monitoring started successfully");
        } else {
            logger.warning("IDS is already running");
        }
    }

    public void stopMonitoring() {
        if (isRunning.compareAndSet(true, false)) {
            logger.info("Stopping IDS monitoring...");

            packetCapture.stopCapture();

            shutdownExecutors();

            loadConfiguration();

            generateShutdownReport();

            logger.info("Monitoring stopped");
        }
    }

    private void onPacketReceived(RawPacket rawPacket) {
        if (!isRunning.get()) {
            return;
        }

        totalPacketsProcessed++;

        if (!packetQueue.offer(rawPacket)) {
            logger.warning("Packet queue full, dropping packet. Consider increasing queue size or processor threads.");
        }
    }

    private void startPacketProcessors() {
        for (int i = 0; i < PROCESSOR_THREADS; i++) {
            packetProcessingPool.submit(this::processPacketsWorker);
        }
    }

    private void processPacketsWorker() {
        while (isRunning.get() || !packetQueue.isEmpty()) {
            try {
                RawPacket rawPacket = packetQueue.poll(1, TimeUnit.SECONDS);

                if (rawPacket != null) {
                    processPacket(rawPacket);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.severe("Error processing packet: " + e.getMessage());
            }
        }
    }

    private void processPacket(RawPacket rawPacket) {
        try {
            PacketInfo packetInfo = parseRawPacket(rawPacket);

            PacketAnalyzer analyzer = new PacketAnalyzer(packetInfo.sourceIP(), packetInfo.destinationIP(), packetInfo.protocol(), packetInfo.timestamp(), packetInfo.packetSize(), packetInfo.destinationPort(), packetInfo.sourcePort());

            List<ThreatDetection> detections = performThreatDetection(analyzer, packetInfo);

            if (!detections.isEmpty()) {
                handleThreatDetections(detections, packetInfo);
            }

            anomalyDetector.updateBaseline(packetInfo);
        } catch (Exception e) {
            logger.severe("Errro analyzing packet: " + e.getMessage());
        }
    }

    private List<ThreatDetection> performThreatDetection(PacketAnalyzer analyzer, PacketInfo packetInfo) {
        List<ThreatDetection> detections = new ArrayList<>();

        List<Signature> matchedSignatures = signatures.findMatches(packetInfo);
        for (Signature signature : matchedSignatures) {
            detections.add(new ThreatDetection(ThreatType.SIGNATURE_MATCH, signature.severity(), "Signature match: " + signature.name(), packetInfo, signature));
        }

        if (analyzer.isPortScan()) {
            detections.add(new ThreatDetection(ThreatType.PORT_SCAN, Severity.HIGH, "Port scan detected from: " + packetInfo.sourceIP(), packetInfo, null));
        }

        if (analyzer.isDDoSAttack()) {
            detections.add(new ThreatDetection(ThreatType.DDOS_ATTACK, Severity.CRITICAL, "DDoS scan detected from: " + packetInfo.sourceIP(), packetInfo, null));
        }

        if (anomalyDetector.isAnomalous(packetInfo)) {
            detections.add(new ThreatDetection(ThreatType.BEHAVIORAL_ANOMALY, Severity.MEDIUM, "Behavioral anomaly detected", packetInfo, null));
        }

        if (isGeographicallyAnomalous(packetInfo)) {
            detections.add(new ThreatDetection(ThreatType.GEO_ANOMALY, Severity.LOW, "Traffic from unusual location", packetInfo, null));
        }

        return detections;
    }

    private void handleThreatDetections(List<ThreatDetection> detections, PacketInfo packetInfo) {
        threatsDetected += detections.size();

        for (ThreatDetection detection : detections) {
            Alert alert = alertManager.createAlert(detection);

            logger.warning(String.format("THREAT DETECTED: %s - %s from %s:%d to %s:%d", detection.threatType(), detection.description(), packetInfo.sourceIP(), packetInfo.sourcePort(), packetInfo.destinationIP(), packetInfo.destinationPort()));

            executeResponseActions(detection, packetInfo);

            updateThreatIntelligence(detection, packetInfo);
        }
    }

    private void executeResponseActions(ThreatDetection detection, PacketInfo packetInfo) {
        ResponseAction action = responseManager.determineAction(detection);

        switch (action.actionType()) {
            case BLOCK_IP:
                responseManager.blockIP(packetInfo.sourceIP(), action.duration());
                logger.info("Blocked IP: " + packetInfo.sourceIP() + " for " + action.duration() + "ms");
                break;

            case RATE_LIMIT:
                responseManager.rateLimitIP(packetInfo.sourceIP(), action.limit());
                logger.info("Rate limited IP: " + packetInfo.sourceIP());
                break;

            case ALERT_ONLY:
                //No action necessary
                break;
            case QUARANTINE:
                responseManager.quarantineIP(packetInfo.sourceIP());
                logger.info("Quarentined IP: " + packetInfo.sourceIP());
                break;
        }
    }

    private void initializeComponents() {
        try {
            List<NetworkInterface> interfaces = getMonitoringInterface();
            packetCapture.initialize(interfaces);

            signatures.loadThreatIntelligence();

            responseManager.initializeFirewallIntegration();

            logger.info("Componenets initialized successfully");
        } catch (Exception e) {
            logger.severe("Failed to initialize components: " + e.getMessage());
            throw new RuntimeException("IDS initialization failed", e);
        }
    }

    private void scheduleMaintenanceTasks() {
        maintenanceScheduler.scheduleWithFixedDelay(PacketAnalyzer::cleanupOldData, MAINTENANCE_INTERVAL, MAINTENANCE_INTERVAL, TimeUnit.SECONDS);

        maintenanceScheduler.scheduleWithFixedDelay(this::generateStatsReport, STATS_REPORT_INTERVAL, STATS_REPORT_INTERVAL, TimeUnit.SECONDS);

        maintenanceScheduler.scheduleWithFixedDelay(signatures::updateSignatures, 3600, 3600, TimeUnit.SECONDS);

        maintenanceScheduler.scheduleWithFixedDelay(responseManager::cleanupExpiredBlocks, 300, 300, TimeUnit.SECONDS);
    }

    private PacketInfo parseRawPacket(RawPacket rawPacket) {
        return new PacketInfo(extractSourceIP(rawPacket), extractDestinationIP(rawPacket), extractProtocol(rawPacket), System.currentTimeMillis(), rawPacket.data().length, extractDestinationPort(rawPacket), extractSourcePort(rawPacket));
    }

    private List<NetworkInterface> getMonitoringInterface() {
        List<NetworkInterface> interfaces = new ArrayList<>();

        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            while (nets.hasMoreElements()) {
                NetworkInterface netInt = nets.nextElement();
                if (netInt.isUp() && !netInt.isLoopback()) {
                    interfaces.add(netInt);
                }
            }
        } catch (SocketException e) {
            logger.severe("Failed to enumerate network interface: " + e.getMessage());
        }

        return interfaces;
    }

    private boolean isGeographicallyAnomalous(PacketInfo packetInfo) {
        return false;
    }

    private void updateThreatIntelligence(ThreatDetection detection, PacketInfo packetInfo) {
        signatures.updateThreatIntelligence(packetInfo.sourceIP(), detection.threatType());
    }

    private void generateStatsReport() {
        logger.info(String.format("IDS Stats: Processed = %d, Threats = %d, Queue = %d, False Positives = %d", totalPacketsProcessed, threatsDetected, packetQueue.size(), falsePositives));
    }

    private void generateShutdownReport() {
        logger.info("=== Shutdown Report ===");
        logger.info("Total packets processes: " + totalPacketsProcessed);
        logger.info("Total threats detected: " + threatsDetected);
        logger.info("False positives: " + falsePositives);
        logger.info("Detection rate: " + (threatsDetected * 100 / totalPacketsProcessed) + "%");
    }

    private void loadConfiguration() {
        config.loadConfiguration();
    }

    private void shutdownExecutors() {
        packetProcessingPool.shutdown();
        maintenanceScheduler.shutdown();

        try {
            if (!packetProcessingPool.awaitTermination(30, TimeUnit.SECONDS)) {
                packetProcessingPool.shutdownNow();
            }

            if (!maintenanceScheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                maintenanceScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            packetProcessingPool.shutdownNow();
            maintenanceScheduler.shutdown();
            Thread.currentThread().interrupt();
        }


    }

    // Placeholder methods for packet parsing
    private String extractSourceIP(RawPacket packet) {
        return "0.0.0.0";
    }

    private String extractDestinationIP(RawPacket packet) {
        return "0.0.0.0";
    }

    private int extractProtocol(RawPacket packet) {
        return 0;
    }

    private int extractSourcePort(RawPacket packet) {
        return 0;
    }

    private int extractDestinationPort(RawPacket packet) {
        return 0;
    }

    // Getter methods for monitoring
    public long getTotalPacketsProcessed() {
        return totalPacketsProcessed;
    }

    public long getThreatsDetected() {
        return threatsDetected;
    }

    public boolean isRunning() {
        return isRunning.get();
    }

    public int getQueueSize() {
        return packetQueue.size();
    }
    
}
