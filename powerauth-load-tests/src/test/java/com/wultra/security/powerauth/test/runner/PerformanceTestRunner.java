package com.wultra.security.powerauth.test.runner;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.wultra.security.powerauth.test.simulation.PerformanceTestSimulation;
import io.gatling.app.Gatling;
import io.gatling.core.config.GatlingPropertiesBuilder;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

public class PerformanceTestRunner {
    public static void main(String[] args) {
        final WireMockServer wireMockServer = new WireMockServer(8090);
        wireMockServer.stubFor(get(urlEqualTo("/mock-callback")).willReturn(aResponse().withBody("Callback ok")));
        wireMockServer.start();
        final GatlingPropertiesBuilder props = new GatlingPropertiesBuilder();
        props.simulationClass(PerformanceTestSimulation.class.getName());

        Gatling.fromMap(props.build());
        wireMockServer.stop();
    }
}
