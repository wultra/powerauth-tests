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
        if (item.getObject() != null) {
            try {
                serializedObject = objectMapper.writeValueAsString(item.getObject());
            } catch (JsonProcessingException e) {
                serializedObject = item.getObject().toString();
            }
        }
        logger.info("Log item with ID: {}, name: {}, description: {}, status: {}, object: {}",
                item.getId(),
                item.getName(),
                item.getDescription(),
                item.getStatus(),
                serializedObject
        );
    }

}
