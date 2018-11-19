/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.provider;

import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthCustomActivationProvider;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Implementation of PowerAuthCustomActivationProvider interface for tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class CustomActivationProvider implements PowerAuthCustomActivationProvider {

    private static String testId;

    @Override
    public String lookupUserIdForAttributes(Map<String, String> identityAttributes) {
        testId = identityAttributes.get("test_id");
        switch (testId) {
            case "TEST_1_COMMIT_PROCESS":
                return identityAttributes.get("username");
            case "TEST_2_NOCOMMIT_NOPROCESS":
                return "static_username";
            default:
                throw new IllegalStateException("Invalid state");
        }
    }

    @Override
    public void processCustomActivationAttributes(Map<String, Object> customAttributes, String activationId, String userId, ActivationType activationType) {
        switch (testId) {
            case "TEST_1_COMMIT_PROCESS":
                customAttributes.remove("key");
                customAttributes.put("key_new", "value_new");
                break;
            case "TEST_2_NOCOMMIT_NOPROCESS":
                break;
            default:
                throw new IllegalStateException("Invalid state");
        }
    }

    @Override
    public boolean shouldAutoCommitActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes) {
        switch (testId) {
            case "TEST_1_COMMIT_PROCESS":
                return true;
            case "TEST_2_NOCOMMIT_NOPROCESS":
                return false;
            default:
                throw new IllegalStateException("Invalid state");
        }
    }
}
