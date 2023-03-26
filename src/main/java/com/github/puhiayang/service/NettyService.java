package com.github.puhiayang.service;

import com.github.puhiayang.bean.ClientRequest;
import com.github.puhiayang.entity.RequestInfoEntity;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.IOException;

@Service
public interface NettyService {
    boolean isCache(HttpRequest req);
    FullHttpResponse getResponseCache(HttpRequest req) throws IOException;
}
