/*
 * PowerAuth test and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.shared.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.SignAndEncryptStep;
import org.junit.jupiter.api.AssertionFailureBuilder;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * Utilities for verifying server responses dependent on protocol versions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ResponseVerificationUtil {

    public static void verifyErrorResponse(BaseStepModel model, ErrorResponse errorResponse) {
        if (model.getVersion().useTemporaryKeys()) {
            assertEquals("ERR_TEMPORARY_KEY", errorResponse.getResponseObject().getCode());
            assertEquals("POWER_AUTH_TEMPORARY_KEY_FAILURE", errorResponse.getResponseObject().getMessage());
        } else {
            assertEquals("ERR_ACTIVATION", errorResponse.getResponseObject().getCode());
            assertEquals("POWER_AUTH_ACTIVATION_INVALID", errorResponse.getResponseObject().getMessage());
        }
    }
}
