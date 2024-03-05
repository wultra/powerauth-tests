package com.wultra.security.powerauth.test.config;

import com.wultra.security.powerauth.test.shared.SharedSessionData;
import io.gatling.javaapi.core.ChainBuilder;
import io.gatling.javaapi.core.FeederBuilder;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import lombok.extern.slf4j.Slf4j;

import static io.gatling.javaapi.core.CoreDsl.exec;
import static io.gatling.javaapi.core.CoreDsl.feed;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.jdbc.JdbcDsl.jdbcFeeder;

@Slf4j
public class PowerAuthLoadTestCommon {

    public static boolean isPreparation = false;

    public static final int NUM_OF_PREPARED_REGISTRATIONS = 1;
    public static final int NUM_OF_PREPARED_OPERATIONS = 1;

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

    public static FeederBuilder<Object> powerauthJdbcFeeder(final String query) {

        return jdbcFeeder("jdbc:postgresql://localhost:5432/powerauth", "powerauth", "", query);
    }

    public static FeederBuilder<Object> dynamicPowerauthJdbcFeeder(final String query, final Boolean dynamic, final String key) {
        final String value = (String) SharedSessionData.transferVariable.get(key);
        final String queryFormatted = query.formatted(value);
        logger.info(queryFormatted);
        return jdbcFeeder("jdbc:postgresql://localhost:5432/powerauth", "powerauth", "", queryFormatted);
    }

}
