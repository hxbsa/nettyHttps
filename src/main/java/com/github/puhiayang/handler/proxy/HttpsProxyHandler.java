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
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.stream.ChunkedFile;
import io.netty.util.Attribute;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

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
    private ByteBuf buf = ByteBufAllocator.DEFAULT.buffer();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.debug("sendToClient：{}", msg);
        logger.debug("进入https处理器------");
        Attribute<ClientRequest> clientRequestAttribute = ctx.channel().attr(CLIENTREQUEST_ATTRIBUTE_KEY);
        ClientRequest clientRequest = clientRequestAttribute.get();
        if (msg instanceof HttpRequest) {
            HttpRequest req = (HttpRequest) msg;
            method = req.method();
            uri = req.uri();
            headers = req.headers();
            // 判断是否走缓存
            isCache = isCache(req);
            isCache = true;
            if (isCache) {
                // 走缓存，构建http相应信息
//                FullHttpResponse rsp = getResponseCache(req);
//                ctx.channel().writeAndFlush(rsp);
                returnStaticFile(req, ctx);
            }
//            if (StringUtils.isEmpty(headers.get("Content-Length"))) {
//                sendToServer(clientRequest, ctx, msg);
//            }
        } else if (msg instanceof HttpContent) {
//            logger.debug("接收HttpContent···");
//            if (!isCache) {
//                HttpContent httpContent = (HttpContent) msg;
//                ByteBuf bufCont = httpContent.content();
//                String sBody = NettyUtil.byteBufToString(bufCont);
//                buf = Unpooled.wrappedBuffer(buf, bufCont);
//                if (msg instanceof DefaultLastHttpContent && !StringUtils.isEmpty(sBody)) {
//                    String url = "https://" + clientRequest.getHost() + uri;
//                    FullHttpRequest req = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, url);
//                    req.headers().set(headers);
//                    if (method.equals(HttpMethod.POST)) {
//                        req.setMethod(HttpMethod.POST);
//                        req.content().clear().writeBytes(buf);
//                    }
//                    sendToServerBody(clientRequest, ctx, msg, req);
//                }
//            }
        } else {
            ByteBuf byteBuf = (ByteBuf) msg;
            // ssl握手
            if (byteBuf.getByte(0) == 22) {
                logger.debug("进入SSL握手--------");
                sendToClient(clientRequest, ctx, msg);
            }
        }
    }

    public void returnStaticFile(HttpRequest req, ChannelHandlerContext ctx) throws Exception {
        logger.info("进入range-----");
        if (req.headers().contains(HttpHeaderNames.RANGE)) {
            // 处理206探测请求
            HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.PARTIAL_CONTENT);
            RandomAccessFile file = new RandomAccessFile("E:\\cache\\ext\\video\\ddd", "r");
            long fileSize = file.length();
            String range = req.headers().get(HttpHeaderNames.RANGE);
            long start = Long.parseLong(range.substring(range.indexOf("=") + 1, range.indexOf("-")));
            long end = fileSize - 1;
            if (range.endsWith("-")) {
                end = fileSize - 1;
            } else {
                end = Long.parseLong(range.substring(range.indexOf("-") + 1));
            }
            long contentLength = end - start + 1;
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, contentLength);
            response.headers().set(HttpHeaderNames.CONTENT_RANGE, "bytes " + start + "-" + end + "/" + fileSize);
            ctx.write(response);
            ChannelFuture sendFileFuture = ctx.write(new ChunkedFile(file, start, contentLength, 8192), ctx.newProgressivePromise());
            sendFileFuture.addListener(new ChannelProgressiveFutureListener() {
                @Override
                public void operationProgressed(ChannelProgressiveFuture future, long progress, long total) throws Exception {
                    if (total < 0) {
                        //System.err.println("Transfer progress: " + progress);
                    } else {
                        //System.err.println("Transfer progress: " + progress + " / " + total);
                    }
                }

                @Override
                public void operationComplete(ChannelProgressiveFuture future) throws Exception {
                    file.close();
                }
            });
            ctx.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT);
        }
    }

    public static boolean isHttps(ChannelHandlerContext ctx) {
        if (ctx.pipeline().get(SslHandler.class) != null) {
            return true;
        }
        return false;
    }

    /**
     * 设置通用响应headers
     *
     * @param response
     */
    private static void setServerHeaders(HttpResponse response) {
        HttpHeaders headers = response.headers();
        headers.set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        headers.set(HttpHeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        headers.set(HttpHeaderNames.ACCESS_CONTROL_ALLOW_CREDENTIALS, true);
        headers.set(HttpHeaderNames.ACCESS_CONTROL_ALLOW_METHODS, "GET,POST,OPTIONS");
        headers.set(HttpHeaderNames.ACCESS_CONTROL_ALLOW_HEADERS, "origin,accept,cookieId,authorization,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,content-length");
        headers.set(HttpHeaderNames.ACCESS_CONTROL_MAX_AGE, 86400);
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
                        ch.pipeline().addLast("httpAggregator", new HttpObjectAggregator(1000 * 1000 * 1024));
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
            ctx.pipeline().addLast("httpAggregator", new HttpObjectAggregator(10 * 10 * 1024));
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
        if (req.uri().equals("/")) {
            return false;
        }
        String localPath = getLocalPath(req);
        File file = new File(localPath);
        if (file.exists()) {
            isCache = true;
        }
        return isCache;
    }


    public FullHttpResponse getResponseCache(HttpRequest req) throws IOException {
        FullHttpResponse rsp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        // 处理图片
        //String jsPath = "E:\\cache\\ext\\antidomxss_v640.js";
        //String pngPath = "E:\\cache\\ext\\video\\V-116823-16A45202";
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
        File file = new File("");
        //缓存
        int bufferSize = (int) file.length();
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[bufferSize];
        int len = 0;
        if ((len = fis.available()) <= data.length) {
            fis.read(data, 0, len);
        }
        fis.close();
        rsp.content().clear().writeBytes(data);
        int size = (int) file.length();
        rsp.headers().set(HttpHeaderNames.CONTENT_TYPE, "video/mp4");
        rsp.headers().set(HttpHeaderNames.CONTENT_LENGTH, (int) file.length());
        return rsp;
    }

    public static void main(String[] args) {
        String hostUrl = StringUtils.substringBefore("/baidu/test?user=123", "?");
        String fileSurf = hostUrl.substring(hostUrl.lastIndexOf("/"));
        System.out.println(fileSurf);
    }

    public String getLocalPath(HttpRequest req) {
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
