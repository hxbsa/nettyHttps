package com.github.puhiayang.handler.response;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.misc.BASE64Encoder;

import java.io.*;
import java.nio.charset.Charset;
import java.util.zip.GZIPInputStream;


/**
 * https代理responseHandler
 * created on 2019/10/28 15:00
 *
 * @author puhaiyang
 */
public class HttpProxyResponseHandler extends ChannelInboundHandlerAdapter {
    private Logger logger = LoggerFactory.getLogger(HttpProxyResponseHandler.class);
    private Channel clientChannel;

    public HttpProxyResponseHandler(Channel clientChannel) {
        this.clientChannel = clientChannel;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        logger.debug("进入返回方法-----");
        if (msg instanceof FullHttpResponse) {
            FullHttpResponse response = (FullHttpResponse) msg;
            logger.debug("[channelRead][FullHttpResponse] 接收到远程的数据1 content:{}", response.content().toString(Charset.defaultCharset()));
        } else if (msg instanceof DefaultHttpResponse) {
            DefaultHttpResponse response = (DefaultHttpResponse) msg;
            logger.debug("[channelRead][FullHttpResponse] 接收到远程的数据 content:{}", response.toString());
        } else if (msg instanceof DefaultHttpContent) {
            DefaultHttpContent httpContent = (DefaultHttpContent) msg;

            logger.debug("[channelRead][DefaultHttpContent] 接收到远程的数据 content:{}");
        } else {
            logger.debug("[channelRead] 接收到远程的数据 " + msg.toString());
        }
        //发送给客户端
        clientChannel.writeAndFlush(msg);
        DefaultHttpContent httpContent = (DefaultHttpContent) msg;
        ByteBuf buf = httpContent.content();
        byte[] ib = new byte[buf.readableBytes()];
        BASE64Encoder encoder = new BASE64Encoder();
        String base64Str = encoder.encode(ib);

        writeImageToDisk(ib, "E:\\cache\\ext\\images\\20220107105619.png");
//        DefaultHttpContent httpContent = (DefaultHttpContent) msg;
//        ByteBuf buf = httpContent.content();
//        String body = "";
//        try {
//            byte[] bytes = new byte[buf.readableBytes()];
//            buf.readBytes(bytes);
//            body = uncompress(bytes);
//            System.out.println();
//        } catch (Exception e) {
//            logger.error("", e);
//        }
        //System.out.println();
    }

    /**
     * gizp数据解压
     * @param bytes
     * @return
     * @throws IOException
     * String
     */
    public static String uncompress(byte[] bytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        GZIPInputStream gunzip = new GZIPInputStream(in);
        byte[] buffer = new byte[256];
        int n;
        while ((n = gunzip.read(buffer))>= 0) {
            out.write(buffer, 0, n);
        }
        // toString()使用平台默认编码，也可以显式的指定如toString("GBK")
        return out.toString();
    }

    /**
     * 将获取的字节数组保存为文件写入硬盘
     *
     * @param data
     * @param fileName
     */
    public static void writeImageToDisk(byte[] data, String fileName) {
        try {
            File file = new File(fileName); // 本地目录
            File fileParent = file.getParentFile();
            if (!fileParent.exists()) {
                fileParent.mkdirs();
                file.createNewFile();
            }
            FileOutputStream fops = new FileOutputStream(file);
            fops.write(data);
            fops.flush();
            fops.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        ctx.close();
        ctx.channel().close();
        ctx.channel().eventLoop().parent().shutdownGracefully();
    }
}
