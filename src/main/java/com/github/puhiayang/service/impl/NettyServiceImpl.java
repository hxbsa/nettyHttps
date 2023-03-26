package com.github.puhiayang.service.impl;

import com.github.puhiayang.bean.ClientRequest;
import com.github.puhiayang.bean.ContentTypeEnum;
import com.github.puhiayang.entity.RequestInfoEntity;
import com.github.puhiayang.service.NettyService;
import io.netty.handler.codec.http.*;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class NettyServiceImpl implements NettyService {

    @Override
    public boolean isCache(HttpRequest req) {
        boolean isCache = false;
        String localPath = getLocalPath(req);
        File file = new File(localPath);
        if(file.exists()) {
            isCache = true;
        }
        return isCache;
    }

    @Override
    public FullHttpResponse getResponseCache(HttpRequest req) throws IOException {
        FullHttpResponse rsp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        // 处理图片
        //String jsPath = "E:\\cache\\ext\\antidomxss_v640.js";
        //String pngPath = "E:\\cache\\ext\\20220107105619.png";
        // content-type
        String centType = "";
        String hostUrl = StringUtils.substringBefore(req.uri(), "?");
        String fileSurf = hostUrl.substring(hostUrl.lastIndexOf("/"));
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
        String localPath = proPath + "ext/cache" + req.uri();
        return localPath;
    }
}
