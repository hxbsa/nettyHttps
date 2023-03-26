package com.github.puhiayang.entity;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import lombok.Data;

@Data
public class RequestInfoEntity {
    private String host;
    private HttpMethod method;
    private String uri;
    private HttpHeaders headers;
}
