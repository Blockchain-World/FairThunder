package FTStreaming;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

public class Provider {

    public static void main(String[] args) {
        // Create Boss group : receiving client connection
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        // Create work group: network read and communication
        EventLoopGroup workGroup = new NioEventLoopGroup();
        // Create start class
        ServerBootstrap bootstrap = new ServerBootstrap();

        try {
            // configuration
            bootstrap.group(bossGroup, workGroup) // set thread group
                    .channel(NioServerSocketChannel.class) //set channel
                    .option(ChannelOption.SO_BACKLOG, 2048) // set the number of thread connections
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel socketChannel) throws Exception {
                            socketChannel.pipeline().addLast(new ProviderHandler());
                        }
                    });
            System.out.println("----- Provider is online, listening on the port " + Config.PROVIDER_PORT + " -----");
            ChannelFuture channelFuture = bootstrap.bind(Config.PROVIDER_PORT).sync();
            channelFuture.channel().closeFuture().sync();
        }  catch (Exception e) {
            e.printStackTrace();
        } finally {
            bossGroup.shutdownGracefully();
            workGroup.shutdownGracefully();
        }
    }
}

