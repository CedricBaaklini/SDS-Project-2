import java.io.*;
import java.util.Properties;
import java.util.logging.Logger;

public class ConfigurationManager {
    private static final Logger logger = Logger.getLogger(ConfigurationManager.class.getName());
    private static final String CONFIG_FILE = "ids.properties";
    private final Properties config = new Properties();

    public void loadConfiguration() {
        try {
            loadDefaultConfiguration();
            loadFromFile();
            logger.info("Configuration loaded successfully");
        } catch (Exception e) {
            logger.severe("Failed to load configuration: " + e.getMessage());
        }
    }

    private void loadDefaultConfiguration() {
        // Default configuration values
        config.setProperty("packet.queue.size", "10000");
        config.setProperty("processor.threads", String.valueOf(Runtime.getRuntime().availableProcessors()));
        config.setProperty("port.scan.threshold", "10");
        config.setProperty("ddos.threshold", "1000");
        config.setProperty("cleanup.interval.minutes", "5");
        config.setProperty("alert.retention.hours", "24");
        config.setProperty("block.default.duration.minutes", "30");
        config.setProperty("enable.auto.blocking", "true");
        config.setProperty("enable.rate.limiting", "true");
        config.setProperty("log.level", "INFO");
    }

    private void loadFromFile() {
        try (InputStream input = new FileInputStream(CONFIG_FILE)) {
            config.load(input);
            logger.info("Loaded configuration from " + CONFIG_FILE);
        } catch (FileNotFoundException e) {
            logger.info("Configuration file not found, using defaults");
            saveConfiguration(); // Create default config file
        } catch (IOException e) {
            logger.warning("Error reading configuration file: " + e.getMessage());
        }
    }

    public void saveConfiguration() {
        try (OutputStream output = new FileOutputStream(CONFIG_FILE)) {
            config.store(output, "IDS Configuration");
            logger.info("Configuration saved to " + CONFIG_FILE);
        } catch (IOException e) {
            logger.severe("Error saving configuration: " + e.getMessage());
        }
    }

    // Getter methods for configuration values
    public int getPacketQueueSize() {
        return Integer.parseInt(config.getProperty("packet.queue.size", "10000"));
    }

    public int getProcessorThreads() {
        return Integer.parseInt(config.getProperty("processor.threads", "4"));
    }

    public int getPortScanThreshold() {
        return Integer.parseInt(config.getProperty("port.scan.threshold", "10"));
    }

    public long getDDoSThreshold() {
        return Long.parseLong(config.getProperty("ddos.threshold", "1000"));
    }

    public long getCleanupIntervalMs() {
        int minutes = Integer.parseInt(config.getProperty("cleanup.interval.minutes", "5"));
        return minutes * 60 * 1000L;
    }

    public boolean isAutoBlockingEnabled() {
        return Boolean.parseBoolean(config.getProperty("enable.auto.blocking", "true"));
    }

    public boolean isRateLimitingEnabled() {
        return Boolean.parseBoolean(config.getProperty("enable.rate.limiting", "true"));
    }

    public long getDefaultBlockDurationMs() {
        int minutes = Integer.parseInt(config.getProperty("block.default.duration.minutes", "30"));
        return minutes * 60 * 1000L;
    }

    public String getProperty(String key, String defaultValue) {
        return config.getProperty(key, defaultValue);
    }

    public void setProperty(String key, String value) {
        config.setProperty(key, value);
    }
}