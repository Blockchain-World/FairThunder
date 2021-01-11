package FTStreaming;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import org.apache.commons.codec.binary.Base64;
import io.netty.util.CharsetUtil;

/**
 * Handling the communication between consumer and deliverer
 */

public class ConsumerFrontendHandler extends SimpleChannelInboundHandler<String> {

    private final String remoteHost;
    private final int remotePort;
    private Channel outboundChannel;

    public ConsumerFrontendHandler(String remoteHost, int remotePort) {
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        closeOnFlush(ctx.channel());
    }

    @Override
    protected void channelRead0(final ChannelHandlerContext ctx, String msg) throws Exception {
        // Received what deliverer sent, start to verify
        // System.out.println(">> Consumer receives chunk from deliverer: " + chunkContent);

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

        // If both hold, start to send key request to provider (Step 2)
        // We assume the key can be received before T_keyResponse times out
        if (sigPVerify && sigDVerify) {
            // sig_consumer_i <- Sign(i||pk_C, sk_C)
            byte[] sig_consumer_i = SignVerify.generateSignature(SignVerify.generateSignKeyPair("CONSUMER").getPrivate(),
                    "keyReq".concat(parsedChunkContent[0]).concat(SignVerify.generateSignKeyPair("CONSUMER").getPublic().toString()).getBytes());
            String sigC = new String(Base64.encodeBase64(sig_consumer_i));
            // (keyReq, i, sigC)
            String keyRequest = "keyReq".concat(Config.SEPARATOR).concat(parsedChunkContent[0]).concat(Config.SEPARATOR).concat(sigC);
            ByteBuf request = Unpooled.copiedBuffer(keyRequest, CharsetUtil.UTF_8);

            if (outboundChannel.isActive()) {
                // Consumer sends the key request to the provider
                outboundChannel.writeAndFlush(request).addListener(new ChannelFutureListener() {
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
        } else {
            System.err.println("Consumer verifies sigP or sigD failed: sigP: " + sigPVerify + ", sigD: " + sigDVerify);
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (outboundChannel != null) {
            closeOnFlush(outboundChannel);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        // System.out.println(">> Consumer connects with the provider ...");
        final Channel inboundChannel = ctx.channel();

        // Start the connection attempt
        Bootstrap b = new Bootstrap();
        b.group(inboundChannel.eventLoop())
                .channel(ctx.channel().getClass())
                .handler(new ConsumerBackendHandler(inboundChannel))
                .option(ChannelOption.AUTO_READ, false);
        ChannelFuture f = b.connect(remoteHost, remotePort);
        outboundChannel = f.channel();

        f.addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception {
                if (future.isSuccess()) {
                    // Connection complete start to read data
                    inboundChannel.read();
                } else {
                    // Close the connection if the connection attempt has failed
                    inboundChannel.close();
                }
            }
        });
    }

    static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }

}
