public record ThreatDetection(ThreatType threatType, Severity severity, String description, PacketInfo packetInfo,
                              Signature signature) {

}
