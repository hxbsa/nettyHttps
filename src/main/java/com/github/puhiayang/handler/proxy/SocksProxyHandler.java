package com.github.puhiayang.handler.proxy;

import com.github.puhiayang.bean.ClientRequest;
import com.github.puhiayang.handler.response.SocksResponseHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.util.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.netty.buffer.ByteBuf;

import static com.github.puhiayang.bean.Constans.CLIENTREQUEST_ATTRIBUTE_KEY;


/**
 * socks的代理handler
 *
 * @author puhaiyang
 * created on 2019/10/25 20:56
 */
public class SocksProxyHandler extends ChannelInboundHandlerAdapter implements IProxyHandler {
    private Logger logger = LoggerFactory.getLogger(HttpsProxyHandler.class);

    private ChannelFuture notHttpReuqstCf;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.debug("[SocksProxyHandler]");
        Attribute<ClientRequest> clientRequestAttribute = ctx.channel().attr(CLIENTREQUEST_ATTRIBUTE_KEY);
        ClientRequest clientRequest = clientRequestAttribute.get();
        sendToServer(clientRequest, ctx, msg);
    }

    @Override
    public void sendToServer(ClientRequest clientRequest, ChannelHandlerContext ctx, Object msg) {
        //不是http请求就不管，全转发出去
        if (notHttpReuqstCf == null) {
            //连接至目标服务器
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(ctx.channel().eventLoop())
                    // 复用客户端连接线程池
                    .channel(ctx.channel().getClass())
                    // 使用NioSocketChannel来作为连接用的channel类
                    .handler(new ChannelInitializer() {
                        @Override
                        protected void initChannel(Channel ch) throws Exception {
                            ch.pipeline().addLast(new SocksResponseHandler(ctx.channel()));
                        }
                    });
            notHttpReuqstCf = bootstrap.connect(clientRequest.getHost(), clientRequest.getPort());
            notHttpReuqstCf.addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture future) throws Exception {
                    if (future.isSuccess()) {
                        future.channel().writeAndFlush(msg);
                    } else {
                        ctx.channel().close();
                    }
                }
            });
        } else {
            notHttpReuqstCf.channel().writeAndFlush(msg);
        }
    }

    @Override
    public void sendToClient(ClientRequest clientRequest, ChannelHandlerContext ctx, Object msg) {
        try {
            // NIO 通信 （传输的数据是什么？ ---------> Buffer 对象）
            ByteBuf buf = (ByteBuf) msg;
            //定义byte数组
            byte[] req = new byte[buf.readableBytes()];
            // 从缓冲区获取数据到 req
            buf.readBytes(req);
            //读取到的数据转换为字符串
            String body = new String(req, "utf-8");
            System.out.println("客户端读取到数据：" + body);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}