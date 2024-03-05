package com.wultra.security.powerauth.test.config;

import io.gatling.javaapi.core.FeederBuilder;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import lombok.Getter;
import lombok.Setter;

import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.jdbc.JdbcDsl.jdbcFeeder;

public class PowerAuthLoadTestCommon {

    public static boolean isPreparation = false;

    public static final int NUM_OF_PREPARED_REGISTRATIONS = 5;
    public static final int NUM_OF_PREPARED_OPERATIONS = 10;

    public static final int NUM_OF_EXECUTED_REGISTRATIONS_TOTAL = 10;
    public static final int NUM_OF_EXECUTED_REGISTRATIONS_MINS = 2;

    public static final String PAC_ADMIN_USER = System.getenv("PAC_ADMIN_USER") != null
            ? System.getenv("PAC_ADMIN_USER") : "system-admin";

    public static final String PAC__ADMIN_PASS = System.getenv("PAC_ADMIN_PASS") != null
            ? System.getenv("PAC_ADMIN_PASS") : "MLUteJ+uvi2EOP/F";
    public static final String PAC_URL = System.getenv("PAC_URL") != null
            ? System.getenv("PAC_URL") : "http://localhost:8089/powerauth-cloud";

    public static final String TEST_SERVER_URL = System.getenv("TEST_SERVER_URL") != null
            ? System.getenv("TEST_SERVER_URL") : "http://localhost:8081";


    public final static HttpProtocolBuilder commonProtocol = http
            .contentTypeHeader("application/json")
            .acceptHeader("application/json")
            .userAgentHeader("PowerAuth-LoadTest/gatling").check();

    public static FeederBuilder<Object> powerauthJdbcFeeder(final String query){
        return jdbcFeeder("jdbc:postgresql://localhost:5432/powerauth", "powerauth", "", query);
    }

}
