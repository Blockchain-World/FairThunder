package FTDownload;

public class Config {

    public static final String ROLE = "DELIVERER";

    public static final String CONSUMER_ADDRESS = "127.0.0.1";
    public static final int CONSUMER_PORT = 8666;

    // Total number of content chunks in downloading
    public static final int CHUNKS = 8;

    // Max frame length
    public static final int FRAMELENGTH = 8 * 1024 * 1024; // 8M

    // Input file location (specified by chunk size, e.g., 256K, 2M)
    public static final String LOCATION = "src/main/resources/input512K.txt";

    public static final String SEPARATOR = ",";
}
