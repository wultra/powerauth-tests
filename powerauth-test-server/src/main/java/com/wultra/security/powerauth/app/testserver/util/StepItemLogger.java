package com.wultra.security.powerauth.app.testserver.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import org.slf4j.Logger;

/**
 * Logging helper class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class StepItemLogger {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void log(Logger logger, StepItem item) {
        if (logger == null || item == null) {
            return;
        }
        String serializedObject = null;
        if (item.object() != null) {
            try {
                serializedObject = objectMapper.writeValueAsString(item.object());
            } catch (JsonProcessingException e) {
                serializedObject = item.object().toString();
            }
        }
        logger.info("Log item with ID: {}, name: {}, description: {}, status: {}, object: {}",
                item.id(),
                item.name(),
                item.description(),
                item.status(),
                serializedObject
        );
    }

}
