/*

 */

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class PacketAnalyzer {
    private static final Map<String, Set<Integer>> portAttempts = new ConcurrentHashMap<>();
    private static final Map<String, List<Long>> packetTimes = new ConcurrentHashMap<>();
    private static final Map<String, Long> trafficVolume = new ConcurrentHashMap<>();
    private static final Map<String, Integer> packetCounts = new ConcurrentHashMap<>();
    private static final int PORT_SCAN_THRESHOLD = 10;
    private static final long PORT_SCAN_TIME_WINDOW = TimeUnit.MINUTES.toMillis(5);
    private static final long DDOS_THRESHOLD = 1000;
    private static final int DDOS_PACKET_COUNT = 100;
    private static final long CLEANUP_INTERVAL = TimeUnit.MINUTES.toMillis(1);
    private final String sourceIP;
    private final String destinationIP;
    private final int protocol;
    private final long timestamp;
    private final int packetSize;
    private final int destinationPort;
    private final int sourcePort;

    public PacketAnalyzer(String sourceIP, String destinationIP, int protocol, long timestamp, int packetSize, int destinationPort, int sourcePort) {
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.protocol = protocol;
        this.timestamp = timestamp;
        this.packetSize = packetSize;
        this.destinationPort = destinationPort;
        this.sourcePort = sourcePort;
    }

    public static void cleanupOldData() {
        long currentTime = System.currentTimeMillis();
        long cutoffTime = currentTime - CLEANUP_INTERVAL;
        
        packetTimes.entrySet().removeIf(entry -> {
            List<Long> times = entry.getValue();
            synchronized (times) {
                times.removeIf(time -> time < cutoffTime);
                return times.isEmpty();
            }
        });
        
        portAttempts.entrySet().removeIf(entry -> entry.getValue().isEmpty());
    }

    public boolean isPortScan() {
        return checkPortScanPattern();
    }

    public boolean isDDoSAttack() {
        return checkTrafficVolume();
    }

    public boolean isSuspiciousTraffic() {
        return checkAnomalies();
    }
    
    private boolean checkPortScanPattern() {
        String key = sourceIP + ":" + destinationIP;

        portAttempts.putIfAbsent(key, ConcurrentHashMap.newKeySet());
        packetTimes.putIfAbsent(key, new ArrayList<>());

        Set<Integer> ports = portAttempts.get(key);
        List<Long> times = packetTimes.get(key);

        ports.add(destinationPort);

        synchronized (times) {
            times.add(timestamp);
            
            times.removeIf(time -> (timestamp - time) > PORT_SCAN_TIME_WINDOW);
        }
        
        if (ports.size() >= PORT_SCAN_THRESHOLD) {
            long oldestValidTime = timestamp - PORT_SCAN_TIME_WINDOW;
            Set<Integer> recentPorts = new HashSet<>();
            
            synchronized (times) {
                for (Long time : times) {
                    if (time >= oldestValidTime) {
                        recentPorts.add(destinationPort);
                    }
                }
            }
            
            if (recentPorts.size() >= PORT_SCAN_THRESHOLD) {
                System.out.println("Port scan detected: " + sourceIP + " -> " + destinationIP + " (" + recentPorts.size() + " ports in " + (PORT_SCAN_TIME_WINDOW / 1000) + "s");
                
                return true;
            }
        }
        
        return checkStealthScan() || checkSequentialPortScan();
    }
    
    private boolean checkTrafficVolume() {
        String sourceKey = sourceIP;
        String destKey = destinationIP;
        
        trafficVolume.merge(sourceKey, (long) packetSize, Long::sum);
        packetCounts.merge(sourceKey, 1, Integer::sum);
        
        packetTimes.putIfAbsent(sourceKey, new ArrayList<>());
        List<Long> times = packetTimes.get(sourceKey);
        
        synchronized (times) {
            times.add(timestamp);
            
            long oneSecondAgo = timestamp - 1000;
            times.removeIf(time -> time < oneSecondAgo);
            
            if (times.size() > DDOS_THRESHOLD) {
                System.out.println("DDOS attack detected: " + sourceIP + " sending " + times.size() + " packets/second");
                
                return true;
            }
            
        }
        
        Integer totalPackets = packetCounts.get(sourceKey);
        Long totalBytes = trafficVolume.get(sourceKey);
        
        if (totalPackets != null && totalPackets > DDOS_PACKET_COUNT) {
            long avgPacketSize = totalBytes / totalPackets;
            
            if (avgPacketSize < 64 && totalPackets > 500) {
                System.out.println("Small packet flood detected: " + sourceIP + " avg size: " + avgPacketSize + " bytes");
                
                return true;
            }
            
            if (avgPacketSize > 1400) {
                System.out.println("Large packet flood detected: " + sourceIP + " avg size: " + avgPacketSize + " bytes");

                return true;
            }
        }
        
        return false;
    }
    
    private boolean checkAnomalies() {
        return checkSuspiciousProtocol() || checkPrivateIPSpoofing() || checkUnusualPacketSize() || checkBroadcastFlood() || checkFragmentedPacketAnomaly();
    }
    
    private boolean checkStealthScan() {
        if (protocol != 6 && protocol != 17 && protocol != 1) {
            if (destinationPort < 1024) {
                System.out.println("Stealth scan detected: Unusual protocol " + protocol + " to port " + destinationPort);
                
                return true;
            }
        }
        
        return false;
    }
    
    private boolean checkSequentialPortScan() {
        String key = sourceIP + ":" + destinationIP;
        Set<Integer> ports = portAttempts.get(key);
        
        if (ports != null && ports.size() > 5) {
            List<Integer> sortedPorts = new ArrayList<>();
            Collections.sort(sortedPorts);
            
            int sequential = 0;
            for (int i = 1; i < sortedPorts.size(); i++) {
                if (sortedPorts.get(i) - sortedPorts.get(i - 1) == 1) {
                    sequential++;
                }
            }
            
            if (sequential > 5) {
                System.out.println("Sequential port scan detected: " + sourceIP);
                return true;
            }
        }
        
        return false;
    }
    
    private boolean checkSuspiciousProtocol() {
        int[] suspiciousProtocols = {2, 4, 41, 50, 51}; // IGMP, IPv4, IPv6, GRE, ESP, AH
        
        for (int suspiciousProto : suspiciousProtocols) {
            if (protocol == suspiciousProto) {
                System.out.println("Suspicious protocol detected: " + protocol + " from " + sourceIP);
            }
            
            return true;
        }
        
        return false;
    }
    
    private boolean checkPrivateIPSpoofing() {
        if (isPrivateIP(sourceIP) && !isPrivateIP(destinationIP)) {
            System.out.println("IP spoofing detected: Private IP " + sourceIP +
                    " in external traffic");
            return true;
        }
        
        if (sourceIP.equals("127.0.0.1") && !destinationIP.equals("127.0.0.1")) {
            System.out.println("IP spoofing detected: Localhost source to external destination");
            return true;
        }
        
        return false;
    }
    
    private boolean checkUnusualPacketSize() {
        if (packetSize < 20) {
            System.out.println("Suspicious packet size: Very small packet (" +
                    packetSize + " bytes) from " + sourceIP);
            return true;
        }

        if (packetSize > 65535) {
            System.out.println("Suspicious packet size: Oversized packet (" +
                    packetSize + " bytes) from " + sourceIP);
            return true;
        }
        
        return false;
    }
    
    private boolean checkSuspiciousPort() {
        int[] suspiciousPorts = {135, 139, 445, 1433, 1434, 3389, 5900, 6000};
        
        for (int suspiciousPort : suspiciousPorts) {
            if (destinationPort == suspiciousPort) {
                System.out.println("Suspicious port access: Port " + destinationPort + " from " + sourceIP);
                return true;
            }
        }
        
        if (destinationPort > 49152 && sourcePort > 49152) {
            System.out.println("High port communication: " + sourceIP + ":" + sourcePort + " -> " + destinationIP + ":" + destinationPort);
            return true;
        }
        
        return false;
    }
    
    private boolean checkBroadcastFlood() {
        if (destinationIP.endsWith(".255") || destinationIP.equals("255.255.255.255")) {
            String key = sourceIP + "_broadcast";
            packetCounts.merge(key, 1, Integer::sum);
            
            if (packetCounts.get(key) > 50) {
                System.out.println("Broadcast flood detected: " + sourceIP + " sent " + packetCounts.get(key) + " broadcasts");
                return true;
            }
        }
        
        return false;
    }
    
    private boolean checkFragmentedPacketAnomaly() {
        if (packetSize == 8 || packetSize == 20 || packetSize == 28) {
            String key = sourceIP + "_fragments";
            packetCounts.merge(key, 1, Integer::sum);
            
            if (packetCounts.get(key) > 100) {
                System.out.println("Fragmentation attack detected: " + sourceIP + " sent " + packetCounts.get(key) + " suspicious fragments");
                return true;
            }
        }
        
        return false;
    }
    
    private boolean isPrivateIP(String ip) {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || (ip.startsWith("172.") && Integer.parseInt(ip.split("\\.")[1]) >= 16 && Integer.parseInt(ip.split("\\.")[1]) <= 31) || ip.startsWith("127.");
    }
}
