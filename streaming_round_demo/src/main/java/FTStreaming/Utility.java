package FTStreaming;

import org.apache.commons.lang3.RandomStringUtils;

/**
 * FairThunder Streaming Utility Class.
 */
public class Utility {

    public static String generateFakeBytes(int size) {
        return RandomStringUtils.randomAlphanumeric(size);
    }

}
