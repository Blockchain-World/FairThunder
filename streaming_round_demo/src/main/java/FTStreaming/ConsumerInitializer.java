package FTStreaming;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.util.CharsetUtil;
import org.apache.commons.lang3.CharSet;


public class ConsumerInitializer extends ChannelInitializer<SocketChannel> {

    private final String remoteHost;
    private final int remotePort;

    public ConsumerInitializer(String remoteHost, int remotePort) {
        this.remoteHost = remoteHost;
        this.remotePort = remotePort;
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        ChannelPipeline pipeline = ch.pipeline();
        pipeline.addLast(
                // new LoggingHandler(LogLevel.INFO),
                new StringEncoder(CharsetUtil.UTF_8),
                new LineBasedFrameDecoder(Config.FRAMELENGTH),
                new StringDecoder(CharsetUtil.UTF_8),
                new ChunkedWriteHandler(),
                new ConsumerFrontendHandler(remoteHost, remotePort)
        );
    }
}
