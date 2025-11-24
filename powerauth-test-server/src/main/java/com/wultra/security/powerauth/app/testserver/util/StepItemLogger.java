/*
 * PowerAuth test and related software components
 * Copyright (C) 2025 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.wultra.security.powerauth.app.testserver.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
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
