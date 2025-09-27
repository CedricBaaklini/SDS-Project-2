import java.time.LocalDateTime;

public record Alert(String id, ThreatType threatType, Severity severity, String description, PacketInfo packetInfo, LocalDateTime timestamp) {
}
