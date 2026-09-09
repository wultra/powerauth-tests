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
package com.wultra.security.powerauth.test.shared.v3;

import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.AuthAndEncryptStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import org.junit.jupiter.api.AssertionFailureBuilder;
import tools.jackson.databind.JsonNode;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth activation rename test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthActivationRenameShared {

    private static final String RESOURCE_ID = "/pa/activation/rename";
    private static final String RENAME_PATH = "/pa/v3/activation/rename";

    public static void renameActivationTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger, PowerAuthVersion version) throws Exception {
        final String newActivationName = "Renamed activation " + UUID.randomUUID();
        signatureModel.setResourceId(RESOURCE_ID);
        signatureModel.setUriString(config.getPowerAuthIntegrationUrl() + RENAME_PATH);
        signatureModel.setData(renameRequestData(config, newActivationName));

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final EciesEncryptedResponse responseOK = (EciesEncryptedResponse) stepLogger.getResponse().responseObject();
        assertNotNull(responseOK.getEncryptedData());
        assertNotNull(responseOK.getMac());

        final JsonNode response = config.getObjectMapper().readTree(fetchDecryptedResponse(stepLogger).toString());
        assertEquals("OK", response.get("status").asText());
        final JsonNode responseObject = response.get("responseObject");
        assertEquals(config.getActivationId(version), responseObject.get("activationId").asText());
        assertEquals(newActivationName, responseObject.get("activationName").asText());
    }

    public static void renameActivationInvalidPasswordTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId(RESOURCE_ID);
        signatureModel.setUriString(config.getPowerAuthIntegrationUrl() + RENAME_PATH);
        signatureModel.setData(renameRequestData(config, "Renamed activation with invalid password"));
        signatureModel.setPassword("0000");

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    public static void renameActivationEmptyNameTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId(RESOURCE_ID);
        signatureModel.setUriString(config.getPowerAuthIntegrationUrl() + RENAME_PATH);
        signatureModel.setData(renameRequestData(config, ""));

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(400, stepLogger.getResponse().statusCode());
    }

    public static void renameActivationWeakSignatureTypeTest(PowerAuthTestConfiguration config, VerifyAuthenticationStepModel signatureModel, ObjectStepLogger stepLogger) throws Exception {
        signatureModel.setResourceId(RESOURCE_ID);
        signatureModel.setUriString(config.getPowerAuthIntegrationUrl() + RENAME_PATH);
        signatureModel.setData(renameRequestData(config, "Renamed activation with weak signature"));
        signatureModel.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION);

        new AuthAndEncryptStep().execute(stepLogger, signatureModel.toMap());
        assertFalse(stepLogger.getResult().success());
        assertEquals(401, stepLogger.getResponse().statusCode());
    }

    private static byte[] renameRequestData(PowerAuthTestConfiguration config, String activationName) {
        return config.getObjectMapper().writeValueAsBytes(Map.of("activationName", activationName));
    }

    private static Object fetchDecryptedResponse(final ObjectStepLogger stepLogger) {
        return stepLogger.getItems().stream()
                .filter(item -> "Decrypted Response".equals(item.name()))
                .map(StepItem::object)
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());
    }

}
