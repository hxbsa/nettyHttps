package com.github.puhiayang;


import com.github.puhiayang.handler.proxy.HttpProxyHandler;
import com.github.puhiayang.handler.proxy.HttpsProxyHandler;
import com.github.puhiayang.handler.proxy.SocksProxyHandler;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.codec.http.cors.CorsConfig;
import io.netty.handler.codec.http.cors.CorsConfigBuilder;
import io.netty.handler.codec.http.cors.CorsHandler;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;


/**
 * EasyHttpProxyServer
 * created on 2019/10/25 14:44
 *
 * @author puhaiyang
 */
public class EasyHttpProxyServer {
    private Logger logger = LoggerFactory.getLogger(EasyHttpProxyServer.class);
    private static EasyHttpProxyServer instace = new EasyHttpProxyServer();

    public static EasyHttpProxyServer getInstace() {
        if (instace == null) {
            instace = new EasyHttpProxyServer();
        }
        return instace;
    }

    public static void main(String[] args) {
        System.out.println("main方法启动");
        int port = 61002;
        if (args.length > 0) {
            port = Integer.valueOf(args[0]);
        }
        new EasyHttpProxyServer().start(port);
    }

    /**
     * 启动
     *
     * @param listenPort 监控的端口
     */
    public void start(int listenPort) {
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup(2);
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000)
                    .option(ChannelOption.SO_BACKLOG, 100)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .option(ChannelOption.SO_RCVBUF, 8192)
                    .handler(new LoggingHandler(LogLevel.INFO))
                    .childHandler(new ChannelInitializer<Channel>() {

                        @Override
                        protected void initChannel(Channel ch) throws Exception {
                            //接收客户端请求，将客户端的请求内容解码
                            ch.pipeline().addLast("httpRequestDecoder", new HttpRequestDecoder());
                            //发送响应给客户端，并将发送内容编码
                            ch.pipeline().addLast("httpResponseEncoder", new HttpResponseEncoder());

                            ch.pipeline().addLast("httpAggregator", new HttpObjectAggregator(10*10*1024));
                            ch.pipeline().addLast("httpProxyHandler", new HttpProxyHandler());
                            ch.pipeline().addLast("streamer", new ChunkedWriteHandler());
                            ch.pipeline().addLast("httpsProxyHandler", new HttpsProxyHandler());
                            CorsConfig corsConfig = CorsConfigBuilder.forAnyOrigin().allowNullOrigin().allowCredentials().build();
                            ch.pipeline().addLast(new CorsHandler(corsConfig));

                        }
                    });
            logger.info("服务启动端口---- port{}", listenPort);
            ChannelFuture f = b
                    .bind(listenPort)
                    .sync();
            f.channel().closeFuture().sync();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
