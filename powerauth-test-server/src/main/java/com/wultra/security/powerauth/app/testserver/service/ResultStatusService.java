/*
 * PowerAuth test and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.testserver.service;

import com.wultra.security.powerauth.app.testserver.database.TestStatusRepository;
import com.wultra.security.powerauth.app.testserver.database.entity.TestStatusEntity;
import com.wultra.security.powerauth.app.testserver.errorhandling.ActivationFailedException;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Optional;

/**
 * Utility service for persistence of result status.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ResultStatusService {

    private final TestStatusRepository appStatusRepository;

    /**
     * Utility service constructor.
     * @param appStatusRepository Test application status repository.
     */
    @Autowired
    public ResultStatusService(TestStatusRepository appStatusRepository) {
        this.appStatusRepository = appStatusRepository;
    }

    /**
     * Utility method for persisting results status object to database.
     * @param resultStatusObject Result status object.
     */
    public void persistResultStatus(JSONObject resultStatusObject) {
        final String activationId = getStringValue(resultStatusObject, "activationId");
        final Optional<TestStatusEntity> statusOptional = appStatusRepository.findById(activationId);
        final TestStatusEntity statusEntity = statusOptional.orElseGet(TestStatusEntity::new);

        final String serverPublicKey = getStringValue(resultStatusObject, "ecServerPublicKey");
        final Long counter = getLongValue(resultStatusObject, "counter");
        final String ctrData = getStringValue(resultStatusObject, "ctrData");
        final String encryptedDevicePrivateKey = getStringValue(resultStatusObject, "encryptedEcDevicePrivateKey");
        final String signatureBiometryKey = getStringValue(resultStatusObject, "biometryFactorKey");
        final String signatureKnowledgeKeyEncrypted = getStringValue(resultStatusObject, "knowledgeFactorKeyEncrypted");
        final String signatureKnowledgeKeySalt = getStringValue(resultStatusObject, "knowledgeFactorKeySalt");
        final String signaturePossessionKey = getStringValue(resultStatusObject, "possessionFactorKey");
        final String sharedSecretAlgorithm = getStringValue(resultStatusObject, "sharedSecretAlgorithm");
        final String temporaryKeyActSignRequestKey = getStringValue(resultStatusObject, "temporaryKeyActSignRequestKey");
        final String pqcServerPublicKey = getStringValue(resultStatusObject, "pqcServerPublicKey");
        final String sharedInfo2Key = getStringValue(resultStatusObject, "sharedInfo2Key");
        final String macPersonalizedDataKey = getStringValue(resultStatusObject, "macPersonalizedDataKey");

        statusEntity.setActivationId(activationId);
        statusEntity.setServerPublicKey(serverPublicKey);
        statusEntity.setCounter(counter);
        statusEntity.setCtrData(ctrData);
        statusEntity.setEncryptedDevicePrivateKey(encryptedDevicePrivateKey);
        statusEntity.setSignatureBiometryKey(signatureBiometryKey);
        statusEntity.setSignatureKnowledgeKeyEncrypted(signatureKnowledgeKeyEncrypted);
        statusEntity.setSignatureKnowledgeKeySalt(signatureKnowledgeKeySalt);
        statusEntity.setSignaturePossessionKey(signaturePossessionKey);
        statusEntity.setSharedSecretAlgorithm(sharedSecretAlgorithm);
        statusEntity.setTemporaryKeyActSignRequestKey(temporaryKeyActSignRequestKey);
        statusEntity.setPqcServerPublicKey(pqcServerPublicKey);
        statusEntity.setSharedInfo2Key(sharedInfo2Key);
        statusEntity.setMacPersonalizedDataKey(macPersonalizedDataKey);

        appStatusRepository.save(statusEntity);
    }

    /**
     * Deserialize the activation status back to JSON Object.
     * @param activationId Activation ID to deserialize.
     * @return Deserialized activation status object.
     * @throws ActivationFailedException In case an activation with given ID does not exist.
     */
    public JSONObject getTestStatus(String activationId) throws ActivationFailedException {
        final TestStatusEntity testStatusEntity = fetchTestStatus(activationId);

        final JSONObject result = new JSONObject();
        result.put("activationId", testStatusEntity.getActivationId());
        result.put("ecServerPublicKey", testStatusEntity.getServerPublicKey());
        result.put("counter", testStatusEntity.getCounter());
        result.put("ctrData", testStatusEntity.getCtrData());
        result.put("encryptedEcDevicePrivateKey", testStatusEntity.getEncryptedDevicePrivateKey());
        result.put("biometryFactorKey", testStatusEntity.getSignatureBiometryKey());
        result.put("knowledgeFactorKeyEncrypted", testStatusEntity.getSignatureKnowledgeKeyEncrypted());
        result.put("knowledgeFactorKeySalt", testStatusEntity.getSignatureKnowledgeKeySalt());
        result.put("possessionFactorKey", testStatusEntity.getSignaturePossessionKey());
        result.put("version", 4L);
        result.put("sharedSecretAlgorithm", testStatusEntity.getSharedSecretAlgorithm());
        result.put("temporaryKeyActSignRequestKey", testStatusEntity.getTemporaryKeyActSignRequestKey());
        result.put("pqcServerPublicKey", testStatusEntity.getPqcServerPublicKey());
        result.put("sharedInfo2Key", testStatusEntity.getSharedInfo2Key());
        result.put("macPersonalizedDataKey", testStatusEntity.getMacPersonalizedDataKey());

        return result;
    }

    public void incrementCounter(String activationId) throws ActivationFailedException {
        final TestStatusEntity testStatusEntity = fetchTestStatus(activationId);

        // Increment numeric counter
        final Long counter = testStatusEntity.getCounter();
        testStatusEntity.setCounter(counter + 1);

        final String ctrDataBase64 = testStatusEntity.getCtrData();

        // Increment hash-based counter
        if (!ctrDataBase64.isEmpty()) {
            byte[] ctrData = Base64.getDecoder().decode(ctrDataBase64);
            try {
                ctrData = new HashBasedCounter(PowerAuthVersion.V4_0.value()).next(ctrData);
            } catch (GenericCryptoException e) {
                logger.warn("Cryptography error occurred: {}", e.getMessage());
                logger.debug(e.getMessage(), e);
                throw new RuntimeException(e);
            }
            testStatusEntity.setCtrData(Base64.getEncoder().encodeToString(ctrData));
        }

        appStatusRepository.save(testStatusEntity);
    }

    private String getStringValue(JSONObject resultStatusObject, String key) {
        return (String) resultStatusObject.get(key);
    }

    private Long getLongValue(JSONObject resultStatusObject, String key) {
        return (Long) resultStatusObject.get(key);
    }

    private TestStatusEntity fetchTestStatus(String activationId) throws ActivationFailedException {
        return appStatusRepository.findById(activationId).orElseThrow(() ->
                new ActivationFailedException("Activation with given ID not found: " + activationId));
    }
}
