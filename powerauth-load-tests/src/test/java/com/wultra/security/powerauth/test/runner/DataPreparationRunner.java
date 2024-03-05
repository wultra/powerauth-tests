package com.wultra.security.powerauth.test.runner;

import com.wultra.security.powerauth.test.simulation.DataPreparationSimulation;
import io.gatling.app.Gatling;
import io.gatling.core.config.GatlingPropertiesBuilder;

public class DataPreparationRunner {
    public static void main(String[] args) {
        final GatlingPropertiesBuilder props = new GatlingPropertiesBuilder();
        props.simulationClass(DataPreparationSimulation.class.getName());

        Gatling.fromMap(props.build());
    }
}
