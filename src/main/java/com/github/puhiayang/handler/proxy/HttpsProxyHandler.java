package com.github.puhiayang.handler.proxy;

import com.github.puhiayang.bean.ClientRequest;
import com.github.puhiayang.bean.ContentTypeEnum;
import com.github.puhiayang.entity.RequestInfoEntity;
import com.github.puhiayang.handler.response.HttpProxyResponseHandler;
import com.github.puhiayang.utils.HttpsSupport;
import com.github.puhiayang.utils.NettyUtil;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.Attribute;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import sun.awt.image.ImageDecoder;

import javax.annotation.PostConstruct;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import static com.github.puhiayang.bean.Constans.CLIENTREQUEST_ATTRIBUTE_KEY;

/**
 * 对https请求进行代理
 * created on 2019/10/25 18:00
 *
 * @author puhaiyang
 */
@Component
public class HttpsProxyHandler extends ChannelInboundHandlerAdapter implements IProxyHandler {
    private Logger logger = LoggerFactory.getLogger(HttpsProxyHandler.class);
    private ChannelFuture httpsRequestCf;
    private HttpMethod method;
    private String uri;
    private HttpHeaders headers;
    private boolean isCache;
    private ByteBuf buf =  ByteBufAllocator.DEFAULT.buffer();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.debug("sendToClient：{}", msg);
        logger.debug("进入https处理器------");
        Attribute<ClientRequest> clientRequestAttribute = ctx.channel().attr(CLIENTREQUEST_ATTRIBUTE_KEY);
        ClientRequest clientRequest = clientRequestAttribute.get();
        if (msg instanceof HttpRequest) {
            HttpRequest req = (HttpRequest)msg;
            method = req.method();
            uri = req.uri();
            headers = req.headers();
            // 判断是否走缓存
            isCache = isCache(req);
            if(isCache){
                // 走缓存，构建http相应信息
                FullHttpResponse rsp = getResponseCache(req);
                ctx.channel().writeAndFlush(rsp);
            }
            if(StringUtils.isEmpty(headers.get("Content-Length"))) {
                sendToServer(clientRequest, ctx, msg);
            }
        } else if (msg instanceof HttpContent) {
            logger.debug("接收HttpContent···");
            if(!isCache) {
                HttpContent httpContent = (HttpContent)msg;
                ByteBuf bufCont = httpContent.content();
                String sBody = NettyUtil.byteBufToString(bufCont);
                buf = Unpooled.wrappedBuffer(buf, bufCont);
                if(msg instanceof DefaultLastHttpContent && !StringUtils.isEmpty(sBody)) {
                    String url = "https://" + clientRequest.getHost() + uri;
                    FullHttpRequest req = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, url);
                    req.headers().set(headers);
                    if(method.equals(HttpMethod.POST)){
                        req .setMethod(HttpMethod.POST);
                        req.content().clear().writeBytes(buf);
                    }
                    sendToServerBody(clientRequest, ctx, msg, req);
                }
            }
        } else {
            ByteBuf byteBuf = (ByteBuf) msg;
            // ssl握手
            if (byteBuf.getByte(0) == 22) {
                logger.debug("进入SSL握手--------");
                sendToClient(clientRequest, ctx, msg);
            }
        }
    }

    public void sendToServerBody(ClientRequest clientRequest, ChannelHandlerContext ctx, Object msg, FullHttpRequest req) {
        logger.debug("进入发送https请求到服务端-------------");
        logger.debug("sendToClient：{}", msg);
        Channel clientChannel = ctx.channel();
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(new NioEventLoopGroup(1))
                // 注册线程池
                .channel(NioSocketChannel.class)
                // 使用NioSocketChannel来作为连接用的channel类
                .handler(new ChannelInitializer() {

                    @Override
                    protected void initChannel(Channel ch) throws Exception {
                        //添加一个ssl处理器进行处理
                        ch.pipeline().addLast(
                                HttpsSupport.getInstance().getClientSslCtx().newHandler(ch.alloc(),
                                        clientRequest.getHost(), clientRequest.getPort()));
                        ch.pipeline().addLast("httpCodec", new HttpClientCodec());
                        //添加响应处理器
                        ch.pipeline().addLast("proxyClientHandle", new HttpProxyResponseHandler(clientChannel));
                    }
                });
        httpsRequestCf = bootstrap.connect(clientRequest.getHost(), clientRequest.getPort());
        //建立连接
         httpsRequestCf.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                future.channel().writeAndFlush(req);
                logger.debug("https建立连接成功------");
            } else {
                logger.error("[HttpsProxyHandler][sendToServer]连接远程server失败");
            }
        });
    }

    @Override
    public void sendToServer(ClientRequest clientRequest, ChannelHandlerContext ctx, Object msg) {
        logger.debug("进入发送https请求到服务端-------------");
        Channel clientChannel = ctx.channel();
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(new NioEventLoopGroup(1))
                // 注册线程池
                .channel(NioSocketChannel.class)
                // 使用NioSocketChannel来作为连接用的channel类
                .handler(new ChannelInitializer() {

                    @Override
                    protected void initChannel(Channel ch) throws Exception {
                        //添加一个ssl处理器进行处理
                        ch.pipeline().addLast(
                                HttpsSupport.getInstance().getClientSslCtx().newHandler(ch.alloc(),
                                        clientRequest.getHost(), clientRequest.getPort()));
                        ch.pipeline().addLast("httpCodec", new HttpClientCodec());
                        //添加响应处理器
                        ch.pipeline().addLast("proxyClientHandle", new HttpProxyResponseHandler(clientChannel));
                    }
                });
        httpsRequestCf = bootstrap.connect(clientRequest.getHost(), clientRequest.getPort());
        //建立连接
        httpsRequestCf.addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                future.channel().writeAndFlush(msg);
                logger.debug("https建立连接成功------");
            } else {
                logger.error("[HttpsProxyHandler][sendToServer]连接远程server失败");
            }
        });
    }

    @Override
    public void sendToClient(ClientRequest clientRequest, ChannelHandlerContext ctx, Object msg) {
        logger.debug("sendToClient：{}", msg);
        try {
            logger.debug("进入与客户端进行https握手方法------");
//            SslProvider provider =
//                    SslProvider.JDK;

//            SelfSignedCertificate ssc = new SelfSignedCertificate();
//            SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().
//                    sslProvider(SslProvider.OPENSSL).clientAuth(ClientAuth.REQUIRE);
//            SslContext sslCtx = sslContextBuilder.build();
//            SslContext sslCtx = SslContextBuilder
//                    .forServer(HttpsSupport.getInstance().getServerPriKey(), HttpsSupport.getInstance().getCert(clientRequest.getHost())).build();
            SslContext sslCtx = SslContextBuilder
                    .forServer(HttpsSupport.getInstance().getServerPriKey(), HttpsSupport.getInstance().getCert(clientRequest.getHost())).build();
            //接收客户端请求，将客户端的请求内容解码
            ctx.pipeline().addFirst("httpRequestDecoder", new HttpRequestDecoder());
            //发送响应给客户端，并将发送内容编码
            ctx.pipeline().addFirst("httpResponseEncoder", new HttpResponseEncoder());
            //http聚合
            ctx.pipeline().addLast("httpAggregator", new HttpObjectAggregator(10*10*1024));
            //ssl处理
            ctx.pipeline().addFirst("sslHandle", sslCtx.newHandler(ctx.alloc()));
            // 重新过一遍pipeline，拿到解密后的的http报文
            ctx.pipeline().fireChannelRead(msg);
            Attribute<ClientRequest> clientRequestAttribute = ctx.channel().attr(CLIENTREQUEST_ATTRIBUTE_KEY);
            clientRequest.setHttps(true);
            clientRequestAttribute.set(clientRequest);
        } catch (Exception e) {
            logger.error("握手报错--- err:{}", e.getMessage());
        }
    }

    public boolean isCache(HttpRequest req) {
        boolean isCache = false;
        if(req.uri().equals("/")) {
            return false;
        }
        String localPath = getLocalPath(req);
        File file = new File(localPath);
        if(file.exists()) {
            isCache = true;
        }
        return isCache;
    }


    public FullHttpResponse getResponseCache(HttpRequest req) throws IOException {
        FullHttpResponse rsp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        // 处理图片
        //String jsPath = "E:\\cache\\ext\\antidomxss_v640.js";
        //String pngPath = "E:\\cache\\ext\\20220107105619.png";
        // content-type
        String centType = "";
        String hostUrl = StringUtils.substringBefore(req.uri(), "?");
        String fileSurf = hostUrl.substring(hostUrl.lastIndexOf("."));
        for (ContentTypeEnum typesEnum : ContentTypeEnum.values()) {
            if (fileSurf.equals(typesEnum.getSurffix())) {
                centType = typesEnum.getCentType();
            }
        }
        String localPath = getLocalPath(req);
        File file = new File(localPath);
        //缓存
        int bufferSize = (int)file.length();
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[bufferSize];
        int len = 0;
        if ((len = fis.available()) <= data.length) {
            fis.read(data, 0, len);
        }
        fis.close();
        rsp.content().clear().writeBytes(data);
        rsp.headers().set(HttpHeaderNames.CONTENT_TYPE, centType);
        rsp.headers().set(HttpHeaderNames.CONTENT_LENGTH, (int)file.length());
        return rsp;
    }

    public static void main(String[] args) {
        String hostUrl = StringUtils.substringBefore("/baidu/test?user=123", "?");
        String fileSurf = hostUrl.substring(hostUrl.lastIndexOf("/"));
        System.out.println(fileSurf);
    }

    public String getLocalPath(HttpRequest req){
        String proPath = StringUtils.substringBefore(System.getProperty("user.dir"), "\\") + "/";
        String localPath = proPath + "cache/ext" + req.uri();
        return localPath;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        ctx.close();
        ctx.channel().close();
        ctx.channel().eventLoop().parent().shutdownGracefully();
    }

}
