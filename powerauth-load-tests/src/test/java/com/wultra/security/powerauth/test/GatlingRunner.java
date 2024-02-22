package com.wultra.security.powerauth.test;

import com.wultra.security.powerauth.test.simulation.RegistrationOperationSimulation;
import io.gatling.app.Gatling;
import io.gatling.core.config.GatlingPropertiesBuilder;

public class GatlingRunner {
    public static void main(String[] args) {

        final String simClass = RegistrationOperationSimulation.class.getName();

        final GatlingPropertiesBuilder props = new GatlingPropertiesBuilder();
        props.simulationClass(simClass);


        Gatling.fromMap(props.build());
    }
}
