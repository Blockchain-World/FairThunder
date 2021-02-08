package FTStreaming;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;
import org.apache.commons.codec.binary.Base64;


public class ProviderHandler extends ChannelInboundHandlerAdapter {

    private String chunkIndex;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        // Received key request from the consumer
        ByteBuf buf = (ByteBuf) msg;
        String keyRequest = buf.toString(CharsetUtil.UTF_8);

        // Verify consumer's signature ("keyReq", i, sigC)
        String[] parsedKeyRequest = keyRequest.split(Config.SEPARATOR);
        chunkIndex = parsedKeyRequest[1];

        boolean sigCVerify = SignVerify.verifySignature(SignVerify.generateSignKeyPair("CONSUMER").getPublic(),
                parsedKeyRequest[0].concat(parsedKeyRequest[1]).concat(SignVerify.generateSignKeyPair("CONSUMER")
                        .getPublic().toString()).getBytes(), Base64.decodeBase64(parsedKeyRequest[2]));
        
        System.out.println("==> " + parsedKeyRequest[1]);
        if (!sigCVerify) {
            throw new Exception("Verify consumer's signature failed!");
        }
        ReferenceCountUtil.release(msg);
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
        // Generate a key of length 32 bytes
        String chunkKey = Utility.generateFakeBytes(32);

        byte[] keySig = SignVerify.generateSignature(SignVerify.generateSignKeyPair("PROVIDER").getPrivate(),
                chunkIndex.concat(chunkKey).getBytes());
        String keySigStr = new String(Base64.encodeBase64(keySig));

        String keyResponse = chunkIndex.concat(Config.SEPARATOR).concat(chunkKey).concat(Config.SEPARATOR).concat(keySigStr);
        // Send the (reveal, i, k_i, sig_k_i) message, namely the chunk key, back to the consumer (Step 3)
        ctx.writeAndFlush(Unpooled.copiedBuffer(keyResponse, CharsetUtil.UTF_8));
    }
}

