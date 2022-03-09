package FTDownload;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;

public class Consumer {

    public static void main(String[] args) throws Exception {
        System.out.println("----- Consumer is online, listening on port " + Config.CONSUMER_PORT + " -----");
        // Configure the bootstrap
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap serverBootstrap = new ServerBootstrap();
            serverBootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    // .option(ChannelOption.SO_BACKLOG, 100)
                    // .handler(new LoggingHandler(LogLevel.INFO))
                    .childHandler(new ConsumerInitializer());
            serverBootstrap.bind(Config.CONSUMER_PORT).sync().channel().closeFuture().sync();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
