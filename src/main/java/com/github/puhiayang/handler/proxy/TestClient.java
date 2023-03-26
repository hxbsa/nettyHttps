package com.github.puhiayang.handler.proxy;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import com.github.puhiayang.EasyHttpProxyServer;
import com.github.puhiayang.utils.SecureChatSslContextFactory;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;

public class TestClient {
    private Logger logger = LoggerFactory.getLogger(EasyHttpProxyServer.class);
    private static EasyHttpProxyServer instace = new EasyHttpProxyServer();

    private ChannelFuture httpsRequestCf;

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
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 3000)
                    .option(ChannelOption.SO_BACKLOG, 100)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .handler(new LoggingHandler(LogLevel.DEBUG))
                    .childHandler(new ChannelInitializer<Channel>() {

                        @Override
                        protected void initChannel(Channel ch) throws Exception {
                            //添加一个ssl处理器进行处理
                            String cChatPath = System.getProperty("user.dir") + "\\easyHttpProxy\\src\\main\\resources\\cChat.jks";
                            SSLEngine engine = SecureChatSslContextFactory.getClientContext(cChatPath)
                                    .createSSLEngine();
                            engine.setUseClientMode(true);
                            ch.pipeline().addLast("sslHandle", new SslHandler(engine));
                            //接收客户端请求，将客户端的请求内容解码
                            ch.pipeline().addLast("httpRequestDecoder", new HttpRequestDecoder());
                            //发送响应给客户端，并将发送内容编码
                            ch.pipeline().addLast("httpResponseEncoder", new HttpResponseEncoder());
                            ch.pipeline().addLast("httpAggregator", new HttpObjectAggregator(10*1024*1024));
                            ch.pipeline().addLast("socksProxyHandler", new HttpServerHandler());
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
        }
    }
}
