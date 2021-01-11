package FTStreaming;

import org.apache.commons.lang3.RandomStringUtils;

/**
 * FairThunder Streaming Utility Class.
 */
public class Utility {

    public static long startTime = 0;
    public static long endTime = 0;

    public static void getStartTime() {
        startTime = System.currentTimeMillis();
    }

    public static void getEndTime() {
        endTime = System.currentTimeMillis();
        System.out.println(">> Total time cost: " + String.valueOf(endTime - startTime) + " us");
    }

    public static String generateFakeBytes(int size) {
        return RandomStringUtils.randomAlphanumeric(size);
    }

}
