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
package com.wultra.security.powerauth.test.shared.v4;

import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.ChangePasswordStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.ChangePasswordStepModel;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth dynamic factor test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthDynamicFactorShared {

    public static void passwordChangeTest(final ChangePasswordStepModel model, final ObjectStepLogger stepLogger) throws Exception {
        new ChangePasswordStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final AeadEncryptedResponse response = (AeadEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(response.getEncryptedData());
        assertNotNull(response.getTimestamp());
    }

}
