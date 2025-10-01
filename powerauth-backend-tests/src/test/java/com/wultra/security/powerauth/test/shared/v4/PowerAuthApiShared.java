/*
 * PowerAuth test and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthenticationResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.client.v4.authentication.PowerAuthClientAuthentication;
import com.wultra.security.powerauth.crypto.client.v4.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.lib.config.AuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.model.BaseStepModel;
import com.wultra.security.powerauth.lib.cmd.util.CounterUtil;
import com.wultra.security.powerauth.lib.cmd.util.EncryptedStorageUtil;
import com.wultra.security.powerauth.lib.cmd.util.JsonUtil;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth server API test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthApiShared {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final PowerAuthClientAuthentication CLIENT_AUTHENTICATION = new PowerAuthClientAuthentication();
    private static final PowerAuthClientKeyFactory KEY_FACTORY = new PowerAuthClientKeyFactory();

    private static final int TIME_SYNCHRONIZATION_WINDOW_SECONDS = 60;

    public static void verifyAuthenticationTest(PowerAuthClient powerAuthClient, PowerAuthTestConfiguration config, PowerAuthVersion version) throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
        Calendar before = new GregorianCalendar();
        before.add(Calendar.SECOND, -TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        byte[] nonceBytes = KEY_GENERATOR.generateRandomBytes(16);
        String data = "test_data";
        String normalizedData = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/pa/auth/validate", nonceBytes, data.getBytes(StandardCharsets.UTF_8));
        String normalizedDataWithSecret = normalizedData + "&" + config.getApplicationSecret();
        byte[] ctrData = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ctrData"));
        byte[] possessionKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "possessionFactorKey"));
        byte[] knowledgeKeySalt = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "knowledgeFactorKeySalt"));
        byte[] knowledgeKeyEncryptedBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "knowledgeFactorKeyEncrypted"));
        SecretKey knowledgeKey = EncryptedStorageUtil.getKnowledgeFactorKey(config.getPassword().toCharArray(), knowledgeKeyEncryptedBytes, knowledgeKeySalt, KEY_GENERATOR);
        SecretKey possessionKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(possessionKeyBytes);
        String authCodeValue = CLIENT_AUTHENTICATION.computeAuthCode(normalizedDataWithSecret.getBytes(StandardCharsets.UTF_8), KEY_FACTORY.keysForAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE,
                possessionKey, knowledgeKey, null), ctrData, AuthenticationCodeConfiguration.base64());
        VerifyAuthenticationResponse signatureResponse = powerAuthClient.verifyAuthentication(config.getActivationId(version), config.getApplicationKey(), normalizedData, authCodeValue, AuthenticationCodeType.POSSESSION_KNOWLEDGE, version.value());
        assertTrue(signatureResponse.isAuthenticationValid());
        BaseStepModel model = new BaseStepModel();
        model.setResultStatusObject(config.getResultStatusObject(version));
        CounterUtil.incrementCounter(model);
        Calendar after = new GregorianCalendar();
        after.add(Calendar.SECOND, TIME_SYNCHRONIZATION_WINDOW_SECONDS);
        List<SignatureAuditItem> auditItems = powerAuthClient.getSignatureAuditLog(config.getUser(version), config.getApplicationId(), before.getTime(), after.getTime());
        boolean signatureFound = auditItems.stream()
                .filter(item -> authCodeValue.equals(item.getSignature()))
                .peek(item -> verifyAuditItem(item, version, config, normalizedDataWithSecret))
                .findFirst()
                .isPresent();
        assertTrue(signatureFound);
    }

    private static void verifyAuditItem(SignatureAuditItem item, PowerAuthVersion version, PowerAuthTestConfiguration config, String normalizedDataWithSecret) {
        assertEquals(config.getActivationId(version), item.getActivationId());
        assertEquals(
                normalizedDataWithSecret,
                new String(Base64.getDecoder().decode(item.getDataBase64()))
        );
        assertEquals(AuthenticationCodeType.POSSESSION_KNOWLEDGE.toString(), item.getSignatureType().toString());
        assertEquals(version.value(), item.getSignatureVersion());
        assertEquals(ActivationStatus.ACTIVE, item.getActivationStatus());
        assertEquals(config.getApplicationId(), item.getApplicationId());
        assertEquals(config.getUser(version), item.getUserId());
        assertEquals(4, item.getVersion());
    }

}