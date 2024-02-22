package com.wultra.security.powerauth.test.scenario;

import com.wultra.security.powerauth.test.SharedSessionData;
import io.gatling.javaapi.core.ChainBuilder;

import static io.gatling.javaapi.core.CoreDsl.exec;

import lombok.extern.slf4j.Slf4j;
import scala.collection.JavaConverters;

import java.util.Map;


@Slf4j
abstract class AbstractScenario {
    public static ChainBuilder prepareSessionData() {
        return exec(session -> {
            for (final Map.Entry<String, Object> entry : SharedSessionData.transferVariable.entrySet()) {
                session = session.set(entry.getKey(), entry.getValue());
            }
            return session;
        });
    }

    public static ChainBuilder saveSessionData() {
        return exec(session -> {
            // Convert Scala Map to Java Map and iterate over all attributes
            JavaConverters.mapAsJavaMapConverter(session.asScala().attributes()).asJava()
                    .forEach((key, value) -> {
                        if (value != null) {
                            SharedSessionData.transferVariable.put(key, value);
                        }
                    });
            return session;
        });
    }
}

