package FTDownload;

import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.SimpleChannelInboundHandler;
import org.apache.commons.codec.binary.Base64;
import io.netty.util.CharsetUtil;

/**
 * Handling the downloading between consumer and deliverer
 */

public class ConsumerHandler extends SimpleChannelInboundHandler<String> {

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        System.out.println(">> Deliverer connected...");
    }

    @Override
    protected void channelRead0(final ChannelHandlerContext ctx, String msg) throws Exception {
        // Received what deliverer sent, start to verify

        Channel inboundChannel = ctx.channel();

        String[] parsedChunkContent = msg.split(Config.SEPARATOR);

        if (parsedChunkContent.length == 0) {
            System.err.println("Cannot separate the message by the SEPARATOR!");
        }
        // chunkContent: i||c_i||sig_c_i||sigD
        // Verify deliverer's signature
        boolean sigDVerify = SignVerify.verifySignature(SignVerify.generateSignKeyPair("DELIVERER").getPublic(),
                parsedChunkContent[0].concat(parsedChunkContent[1]).concat(parsedChunkContent[2]).getBytes(), Base64.decodeBase64(parsedChunkContent[3]));

        // Verify provider's signature (namely sig_c_i)
        boolean sigPVerify = SignVerify.verifySignature(SignVerify.generateSignKeyPair("PROVIDER").getPublic(),
                parsedChunkContent[0].concat(parsedChunkContent[1]).getBytes(), Base64.decodeBase64(parsedChunkContent[2]));

        // If valid, send back the receipt to acknowledge deliverer's bandwidth contribution
        if (sigPVerify && sigDVerify) {
            // Prepare receipt and send back to the deliverer (by consumer) for requesting the next chunk
            // sig_i_CD <- Sign("receipt"||i||pk_C||pk_D, sk_C)
            String receiptPrefix = "receipt";
            byte[] receiptSig = SignVerify.generateSignature(SignVerify.generateSignKeyPair("CONSUMER").getPrivate(),
                    receiptPrefix.concat(parsedChunkContent[0]).concat(SignVerify.generateSignKeyPair("CONSUMER").getPublic().toString())
                            .concat(SignVerify.generateSignKeyPair("DELIVERER").getPublic().toString()).getBytes());
            String sig_i_CD = new String(Base64.encodeBase64(receiptSig));

            // receipt := ("receipt",i,sig_i_CD)
            String receipt = receiptPrefix.concat(Config.SEPARATOR).concat(parsedChunkContent[0]).concat(Config.SEPARATOR).concat(sig_i_CD) + '\n';

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

        } else {
            System.err.println("Consumer verifies sigP or sigD failed: sigP: " + sigPVerify + ", sigD: " + sigDVerify);
        }
    }


    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
        ctx.flush();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        ctx.close();
    }

}
