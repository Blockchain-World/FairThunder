package FTStreaming;

public class Config {

    public static final String ROLE = "PROVIDER";

    public static final String PROVIDER_ADDRESS = "127.0.0.1";
    public static final int PROVIDER_PORT = 8664;

    public static final String DELIVERER_ADDRESS = "127.0.0.1";
    public static final int DELIVERER_PORT = 8665;

    public static final String CONSUMER_ADDRESS = "127.0.0.1";
    public static final int CONSUMER_PORT = 8666;

    // Max frame length
    public static final int FRAMELENGTH = 4 * 1024 * 1024; // 4M

    // Input file location (specified by chunk size, e.g., 256K, 2M)
    public static final String LOCATION = "src/main/resources/input2M.txt";

    public static final String SEPARATOR = ",";

}
