package FTStreaming;

public class Config {

    public static final String ROLE = "PROVIDER";

    // Provider's IP address and port
    public static final String PROVIDER_ADDRESS = "XXX_PROVIDER_ADDRESS_XXX";
    public static final int PROVIDER_PORT = "XXX_PROVIDER_PORT_XXX";

    // Deliverer's IP address and port
    public static final String DELIVERER_ADDRESS = "XXX_DELIVERER_ADDRESS_XXX";
    public static final int DELIVERER_PORT = "XXX_DELIVERER_PORT_XXX";

    // Consumer's IP address and port
    public static final String CONSUMER_ADDRESS = "XXX_CONSUMER_ADDRESS_XXX";
    public static final int CONSUMER_PORT = "XXX_CONSUMER_PORT_XXX";

    // Max Frame Length
    public static final int FRAMELENGTH = 4 * 1024 * 1024; // 4M

    // Input File Location (specified by chunk size, e.g., 256K, 2M)
    public static final String LOCATION = "src/main/resources/input2M.txt";

    public static final String SEPARATOR = ",";

}
