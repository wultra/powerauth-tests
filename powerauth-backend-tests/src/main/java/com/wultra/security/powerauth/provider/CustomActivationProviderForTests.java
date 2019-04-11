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

import io.getlime.security.powerauth.rest.api.base.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of PowerAuthCustomActivationProvider interface for tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class CustomActivationProviderForTests implements CustomActivationProvider {

    private static String testId;

    @Override
    public String lookupUserIdForAttributes(Map<String, String> identityAttributes) {
        testId = identityAttributes.get("test_id");
        Map<String, String> userNameToUserIdMap = new HashMap<>();
        userNameToUserIdMap.put("TestUser1", "12345678");

        switch (testId) {
            case "TEST_1_SIMPLE_LOOKUP_COMMIT_PROCESS":
                return identityAttributes.get("username");
            case "TEST_2_STATIC_NOCOMMIT_NOPROCESS":
                return "static_username";
            case "TEST_3_USER_ID_MAP_COMMIT_NOPROCESS":
                return userNameToUserIdMap.get(identityAttributes.get("username"));
            default:
                // Default action for negative tests
                return identityAttributes.get("username");
        }
    }

    @Override
    public Map<String, Object> processCustomActivationAttributes(Map<String, Object> customAttributes, String activationId, String userId, ActivationType activationType) {
        Map<String, Object> processedCustomAttributes = new HashMap<>(customAttributes);
        switch (testId) {
            case "TEST_1_SIMPLE_LOOKUP_COMMIT_PROCESS":
                processedCustomAttributes.remove("key");
                processedCustomAttributes.put("key_new", "value_new");
                break;
            case "TEST_2_STATIC_NOCOMMIT_NOPROCESS":
                break;
            case "TEST_3_USER_ID_MAP_COMMIT_NOPROCESS":
                break;
            default:
                // Default action for negative tests - do nothing
        }
        return processedCustomAttributes;
    }

    @Override
    public boolean shouldAutoCommitActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String activationId, String userId, ActivationType activationType) {
        switch (testId) {
            case "TEST_1_SIMPLE_LOOKUP_COMMIT_PROCESS":
                return true;
            case "TEST_2_STATIC_NOCOMMIT_NOPROCESS":
                return false;
            case "TEST_3_USER_ID_MAP_COMMIT_NOPROCESS":
                return true;
            default:
                // Default action for negative tests
                return true;
        }
    }

    @Override
    public void activationWasCommitted(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String activationId, String userId, ActivationType activationType) {
        // Ignore
    }

    @Override
    public Integer getMaxFailedAttemptCount(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String userId, ActivationType activationType) {
        // Set max failed attempt count to 3
        return 3;
    }

    @Override
    public Integer getValidityPeriodDuringActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String userId, ActivationType activationType) {
        // Return 10 seconds as validity period
        return 10000;
    }
}
