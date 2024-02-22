package com.wultra.security.powerauth.test.config;

import io.gatling.javaapi.http.HttpProtocolBuilder;

import static io.gatling.javaapi.http.HttpDsl.http;

public class PowerAuthCommon {

    public static final String powerAuthCloudUrl = System.getProperty("powerAuthJavaServerUrl", "http://localhost:8089/powerauth-cloud/");
    public static final String powerAuthTestServerUrl = System.getProperty("powerAuthJavaServerUrl", "http://localhost:8081/");
    public final static HttpProtocolBuilder commonProtocol = http
            .contentTypeHeader("application/json")
            .acceptHeader("application/json")
            .userAgentHeader("PowerAuth-LoadTest/gatling").check();

}
