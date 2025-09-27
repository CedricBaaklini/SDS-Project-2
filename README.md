## Detection Capabilities

### Traffic Volume Anomalies

- Monitors packet rates per IP address
- Uses statistical thresholds to identify spikes or drops in traffic

### Port Access Anomalies

- Tracks normal port access patterns over time
- Flags access to high-numbered ports (>49152) as potentially suspicious
- Analyzes temporal access patterns

### Protocol Anomalies

- Focuses on common protocols (ICMP, TCP, UDP)
- Detects unusual packet sizes for specific protocols
- Flags uncommon protocol usage

### Timing Anomalies

- Identifies suspiciously regular intervals between packets
- Detects automated/scripted behavior patterns

### Attack Pattern Detection

- **Port Scanning**: Detects systematic port enumeration attempts
- **DDoS Attacks**: Identifies distributed denial of service patterns
- **IP Spoofing**: Validates IP address authenticity
- **Protocol Anomalies**: Flags unusual protocol usage patterns

## Requirements

- Java SDK 24+
- Maven (for dependency management)
- No external dependencies (uses standard Java libraries only)

## Build and Installation

### Using Maven

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd SDS-Project-2
   ```

2. **Build with Maven**:
   ```bash
   mvn clean compile
   ```

3. **Run the application**:
   ```bash
   mvn exec:java -Dexec.mainClass="Main"
   ```

### Manual Compilation

1. **Compile the project**:
   ```bash
   javac src/main/java/*.java
   ```

2. **Run the application**:
   ```bash
   java -cp src/main/java Main
   ```

3. **Input data**: The system automatically loads IP addresses from `ips.txt` and simulates network traffic for testing.

4. **Monitoring**: The system will display real-time threat detection and statistics. Press Enter to stop monitoring.

## Alert Severity Levels

- **CRITICAL**: Immediate threats requiring urgent attention (e.g., active DDoS attacks)
- **HIGH**: Serious security concerns (e.g., port scanning attempts)
- **MEDIUM**: Behavioral anomalies requiring investigation
- **LOW**: Minor suspicious activities (e.g., geographical anomalies)

## Response Actions

The system can automatically respond to detected threats:

- **BLOCK_IP**: Temporarily or permanently block malicious IP addresses
- **RATE_LIMIT**: Apply traffic rate limiting to suspicious sources
- **QUARANTINE**: Isolate potentially compromised systems
- **ALERT_ONLY**: Log and notify without automated intervention

## Performance Considerations

- Uses `ConcurrentHashMap` for thread-safe baseline storage
- Maintains rolling windows to prevent memory bloat
- Configurable baseline windows for memory/accuracy trade-offs
- Multithreaded packet processing for high throughput
- Automatic cleanup of old data and expired blocks

## Extending the System

The modular design allows for easy extension:

- **Custom Detection Rules**: Add new anomaly detection methods to `AnomalyDetector`
- **Threat Intelligence Sources**: Extend `SignatureDatabase` with additional data sources
- **Response Actions**: Implement custom response strategies in `ResponseManager`
- **Alert Integrations**: Add new notification channels in `AlertManager`
- **Packet Capture**: Integrate with real network interfaces for live monitoring

## Testing and Simulation

The system includes comprehensive traffic simulation capabilities:

- **Normal Traffic Simulation**: Generates baseline traffic patterns
- **Attack Simulation**: Tests port scanning, DDoS, and other attack vectors
- **Invalid IP Testing**: Validates system response to malformed data
- **Performance Testing**: Stress tests with high packet volumes

## Security Note

This system is designed for network security monitoring and should be deployed in accordance with your organization's
security policies and applicable laws regarding network monitoring.

## Logging and Monitoring

- Comprehensive logging with Java's built-in logging framework
- Real-time statistics reporting
- Alert correlation and trend analysis
- Performance metrics tracking

## Dependencies

The project uses Maven for dependency management. Key dependencies include:

- **Java SDK 24**: Core runtime environment
- **JetBrains Annotations**: Code quality annotations (optional)
- Standard Java libraries for concurrent processing, networking, and logging