public record PacketInfo(String sourceIP, String destinationIP, int protocol, long timestamp, int packetSize,
                         int destinationPort, int sourcePort) {

}
