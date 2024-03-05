package com.wultra.security.powerauth.test.config;

import io.gatling.javaapi.core.FeederBuilder;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import lombok.extern.slf4j.Slf4j;

import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.jdbc.JdbcDsl.jdbcFeeder;

@Slf4j
public class PowerAuthLoadTestCommon {

    public static final String PERF_TEST_PREP_N_REG = System.getenv("PERF_TEST_PREP_N_REG") != null
            ? System.getenv("PERF_TEST_PREP_N_REG") : "100";
    public static final String PREP_TEST_PREP_M_OP = System.getenv("PREP_TEST_PREP_M_OP") != null
            ? System.getenv("PREP_TEST_PREP_M_OP") : "10";

    public static final String PERF_TEST_EXE_X_REG = System.getenv("PERF_TEST_EXE_X_REG") != null
            ? System.getenv("PERF_TEST_EXE_X_REG") : "10";

    public static final String PERF_TEST_EXE_Y_REG = System.getenv("PERF_TEST_EXE_Y_REG") != null
            ? System.getenv("PERF_TEST_EXE_Y_REG") : "6";

    public static final String PERF_TEST_EXE_MIN = System.getenv("PERF_TEST_EXE_MIN") != null
            ? System.getenv("PERF_TEST_EXE_MIN") : "10";

    public static final String PAC_ADMIN_USER = System.getenv("PAC_ADMIN_USER") != null
            ? System.getenv("PAC_ADMIN_USER") : "system-admin";

    public static final String PAC__ADMIN_PASS = System.getenv("PAC_ADMIN_PASS") != null
            ? System.getenv("PAC_ADMIN_PASS") : "";
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

}
