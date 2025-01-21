/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2020 Wultra s.r.o.
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
package com.wultra.security.powerauth.controller;

import com.wultra.core.rest.model.base.response.Response;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Test controller for callbacks.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController
public class CallbackTestController {

    private final Map<String, Map<String, Object>> callbacks = new HashMap<>();
    private static final int CALLBACK_VERIFY_MAX_ATTEMPTS = 100;

    @RequestMapping("/callback/post")
    public Response recordCallback(@RequestBody Map<String, Object> request) {
        String activationId = request.get("activationId").toString();
        callbacks.put(activationId, request);
        return new Response();
    }

    @RequestMapping("/callback/verify")
    public Response verifyCallback(@RequestBody Map<String, Object> request) {
        String activationId = request.get("activationId").toString();
        int counter = 0;
        while (!callbacks.containsKey(activationId)) {
            counter++;
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }
            if (counter > CALLBACK_VERIFY_MAX_ATTEMPTS) {
                throw new IllegalStateException("Callback was not found for activation ID: " + activationId);
            }
        }
        return new Response();
    }

}
