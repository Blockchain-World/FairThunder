package FTStreaming;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.DefaultFileRegion;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.CharsetUtil;
import org.apache.commons.codec.binary.Base64;
import java.io.RandomAccessFile;

public class DelivererHandler extends SimpleChannelInboundHandler<String> {

    public static int currentChunkIndex = 1;
    public static long startTime = 0;
    public static long tempTime = 0;

    public static String prepareChunk() throws Exception {
        // Chunk index
        int i = currentChunkIndex++;
        // Prepare content chunk c_i
        String c_i = "";
        RandomAccessFile randomAccessFile = null;
        long length = -1;

        try {
            randomAccessFile = new RandomAccessFile(Config.LOCATION, "r");
            randomAccessFile.seek(0);
            c_i = randomAccessFile.readLine();
            length = randomAccessFile.length();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (length < 0 && randomAccessFile != null) {
                randomAccessFile.close();
            }
        }
        
        // Prepare the signature (i.e., sig_{c_i} in deliver message) representing that c_i is signed by the provider
        // sig_c_i <- Sign(i||c_i, sk_P)
        byte[] sig_c_i = SignVerify.generateSignature(SignVerify.generateSignKeyPair("PROVIDER").getPrivate(),
                String.valueOf(i).concat(c_i).getBytes());

        // The deliverer C signs the sent-out message: (i||c_i||sig_c_i)
        byte[] sig_d_i = SignVerify.generateSignature(SignVerify.generateSignKeyPair("DELIVERER").getPrivate(),
                String.valueOf(i).concat(c_i).concat(new String(Base64.encodeBase64(sig_c_i))).getBytes());
        String sigD = new String(Base64.encodeBase64(sig_d_i));

        // i||c_i||sig_c_i||sigD
        String sig_c_i_encoded = new String(Base64.encodeBase64(sig_c_i));
        String chunkContent = String.valueOf(i).concat(Config.SEPARATOR).concat(c_i).concat(Config.SEPARATOR)
                .concat(sig_c_i_encoded).concat(Config.SEPARATOR).concat(sigD);
        return chunkContent;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        String chunkContent = prepareChunk();
        startTime = System.currentTimeMillis();
        // The deliverer sends out the (deliver) message (Step 1)
        // We consider that the receipt can be received before T_chunkReceipt times out
        ctx.writeAndFlush(chunkContent + '\n');
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        // Receive receipt from the consumer for the delivered (encrypted) chunk
        // Receipt: ("receipt", i, sig_i_CD), and sig_i_CD <- Sign("receipt"||i||pk_C||pk_D, sk_C)
        String[] parsedReceipt = msg.split(Config.SEPARATOR);

        // Verify the signature of the receipt sent by consumer
        boolean receiptVerify = SignVerify.verifySignature(SignVerify.generateSignKeyPair("CONSUMER").getPublic(),
                parsedReceipt[0].concat(parsedReceipt[1]).concat(SignVerify.generateSignKeyPair("CONSUMER").getPublic().toString())
                        .concat(SignVerify.generateSignKeyPair("DELIVERER").getPublic().toString()).getBytes(), Base64.decodeBase64(parsedReceipt[2]));

        if (receiptVerify) {
            // Print out the round delay
            tempTime = System.currentTimeMillis() - startTime + tempTime;
            System.out.println("=> " + tempTime + " ms");
        } else {
            System.out.println("Failed!");
        }
        System.out.println("--- " + parsedReceipt[1] + " ----");
        if (Integer.parseInt(parsedReceipt[1]) >= Config.CHUNKS) {
            return;
        } else {
            String chunkContent = prepareChunk();
            startTime = System.currentTimeMillis();
            ctx.writeAndFlush(chunkContent + '\n');
        }
    }
}

