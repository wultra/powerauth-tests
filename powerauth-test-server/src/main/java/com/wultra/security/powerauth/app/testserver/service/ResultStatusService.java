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
import io.getlime.security.powerauth.crypto.lib.generator.HashBasedCounter;
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

        final String serverPublicKey = getStringValue(resultStatusObject, "serverPublicKey");
        final Long counter = getLongValue(resultStatusObject, "counter");
        final String ctrData = getStringValue(resultStatusObject, "ctrData");
        final String encryptedDevicePrivateKey = getStringValue(resultStatusObject, "encryptedDevicePrivateKey");
        final String signatureBiometryKey = getStringValue(resultStatusObject, "signatureBiometryKey");
        final String signatureKnowledgeKeyEncrypted = getStringValue(resultStatusObject, "signatureKnowledgeKeyEncrypted");
        final String signatureKnowledgeKeySalt = getStringValue(resultStatusObject, "signatureKnowledgeKeySalt");
        final String signaturePossessionKey = getStringValue(resultStatusObject, "signaturePossessionKey");
        final String transportMasterKey = getStringValue(resultStatusObject, "transportMasterKey");

        statusEntity.setActivationId(activationId);
        statusEntity.setServerPublicKey(serverPublicKey);
        statusEntity.setCounter(counter);
        statusEntity.setCtrData(ctrData);
        statusEntity.setEncryptedDevicePrivateKey(encryptedDevicePrivateKey);
        statusEntity.setSignatureBiometryKey(signatureBiometryKey);
        statusEntity.setSignatureKnowledgeKeyEncrypted(signatureKnowledgeKeyEncrypted);
        statusEntity.setSignatureKnowledgeKeySalt(signatureKnowledgeKeySalt);
        statusEntity.setSignaturePossessionKey(signaturePossessionKey);
        statusEntity.setTransportMasterKey(transportMasterKey);

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
        result.put("serverPublicKey", testStatusEntity.getServerPublicKey());
        result.put("counter", testStatusEntity.getCounter());
        result.put("ctrData", testStatusEntity.getCtrData());
        result.put("encryptedDevicePrivateKey", testStatusEntity.getEncryptedDevicePrivateKey());
        result.put("signatureBiometryKey", testStatusEntity.getSignatureBiometryKey());
        result.put("signatureKnowledgeKeyEncrypted", testStatusEntity.getSignatureKnowledgeKeyEncrypted());
        result.put("signatureKnowledgeKeySalt", testStatusEntity.getSignatureKnowledgeKeySalt());
        result.put("signaturePossessionKey", testStatusEntity.getSignaturePossessionKey());
        result.put("transportMasterKey", testStatusEntity.getTransportMasterKey());
        result.put("version", 3L);

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
            ctrData = new HashBasedCounter().next(ctrData);
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
