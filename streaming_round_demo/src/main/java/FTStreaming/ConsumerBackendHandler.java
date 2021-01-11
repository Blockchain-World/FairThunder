package FTStreaming;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.util.CharsetUtil;
import org.apache.commons.codec.binary.Base64;

/**
 * Handling the communication between consumer and provider
 */

public class ConsumerBackendHandler extends ChannelInboundHandlerAdapter {

    private final Channel inboundChannel;

    public ConsumerBackendHandler(Channel inboundChannel) {
        this.inboundChannel = inboundChannel;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ctx.read();
    }

    @Override
    public void channelRead( final ChannelHandlerContext ctx, Object msg) throws Exception {
        // Provider responds with chunk key (chunkIndex, chunkKey, keySig)
        ByteBuf buf = (ByteBuf) msg;
        String chunkKey = buf.toString(CharsetUtil.UTF_8);
        String[] parsedChunkKey = chunkKey.split(Config.SEPARATOR);

        // Verify provider's signature
        boolean sigPVerify = SignVerify.verifySignature(SignVerify.generateSignKeyPair("PROVIDER").getPublic(),
                parsedChunkKey[0].concat(parsedChunkKey[1]).getBytes(), Base64.decodeBase64(parsedChunkKey[2]));

        System.out.println("sigPVerify: " + sigPVerify);

        if (sigPVerify) {
            // Prepare receipt and send back to the deliverer (by consumer) for requesting the next chunk (Step 5.a)
            // For the one-round communication, the receipts for the deliverer and the provider can be sent out simultaneously
            // Therefore, one side communication (e.g., with the deliverer) is sufficient to estimate the delay
            // sig_i_CD <- Sign("receipt"||i||pk_C||pk_D, sk_C)
            String receiptPrefix = "receipt";
            byte[] receiptSig = SignVerify.generateSignature(SignVerify.generateSignKeyPair("CONSUMER").getPrivate(), receiptPrefix.concat(parsedChunkKey[0])
                                                            .concat(SignVerify.generateSignKeyPair("CONSUMER").getPublic().toString())
                                                            .concat(SignVerify.generateSignKeyPair("DELIVERER").getPublic().toString()).getBytes());
            String sig_i_CD = new String(Base64.encodeBase64(receiptSig));

            String receipt = receiptPrefix.concat(Config.SEPARATOR).concat(parsedChunkKey[0]).concat(Config.SEPARATOR).concat(sig_i_CD) + '\n';

            inboundChannel.writeAndFlush(Unpooled.copiedBuffer(receipt, CharsetUtil.UTF_8)).addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture future) throws Exception {
                    if (future.isSuccess()) {
                        ctx.channel().read();
                    } else {
                        future.channel().close();
                    }
                }
            });
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        ConsumerFrontendHandler.closeOnFlush(inboundChannel);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        ConsumerFrontendHandler.closeOnFlush(ctx.channel());
    }
}
