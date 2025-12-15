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
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import com.wultra.security.powerauth.crypto.lib.generator.HashBasedCounter;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
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
     * @param resultStatus Result status object.
     */
    public void persistResultStatus(ResultStatusObject resultStatus) {

        final String activationId = resultStatus.getActivationId();
        final Optional<TestStatusEntity> statusOptional = appStatusRepository.findById(activationId);
        final TestStatusEntity statusEntity = statusOptional.orElseGet(TestStatusEntity::new);

        final String ecServerPublicKey = resultStatus.getEcServerPublicKey();
        final String pqcServerPublicKey = resultStatus.getPqcServerPublicKey();
        final String ecDevicePublicKey = resultStatus.getEcDevicePublicKey();
        final String pqcDevicePublicKey = resultStatus.getPqcDevicePublicKey();
        final Long counter = resultStatus.getCounter();
        final String ctrData = resultStatus.getCtrData();
        final String encryptedEcDevicePrivateKey = resultStatus.getEncryptedEcDevicePrivateKey();
        final String encryptedPqcDevicePrivateKey = resultStatus.getEncryptedPqcDevicePrivateKey();
        final String biometryFactorKey = resultStatus.getBiometryFactorKey();
        final String knowledgeFactorKeyEncrypted = resultStatus.getKnowledgeFactorKeyEncrypted();
        final String knowledgeFactorKeySalt = resultStatus.getKnowledgeFactorKeySalt();
        final String possessionFactorKey = resultStatus.getPossessionFactorKey();
        final String sharedSecretAlgorithm = resultStatus.getSharedSecretAlgorithm();
        final String temporaryKeyActSignRequestKey = resultStatus.getTemporaryKeyActSignRequestKey();
        final String sharedInfo2Key = resultStatus.getSharedInfo2Key();
        final String macPersonalizedDataKey = resultStatus.getMacPersonalizedDataKey();
        final String statusBlobMacKey = resultStatus.getStatusBlobMacKey();
        final String transportMasterKey = resultStatus.getTransportMasterKey();
        final Long version = resultStatus.getVersion();

        statusEntity.setActivationId(activationId);
        statusEntity.setEcServerPublicKey(ecServerPublicKey);
        statusEntity.setPqcServerPublicKey(pqcServerPublicKey);
        statusEntity.setEcDevicePublicKey(ecDevicePublicKey);
        statusEntity.setPqcDevicePublicKey(pqcDevicePublicKey);
        statusEntity.setCounter(counter);
        statusEntity.setCtrData(ctrData);
        statusEntity.setEncryptedEcDevicePrivateKey(encryptedEcDevicePrivateKey);
        statusEntity.setEncryptedPqcDevicePrivateKey(encryptedPqcDevicePrivateKey);
        statusEntity.setBiometryFactorKey(biometryFactorKey);
        statusEntity.setKnowledgeFactorKeyEncrypted(knowledgeFactorKeyEncrypted);
        statusEntity.setKnowledgeFactorKeySalt(knowledgeFactorKeySalt);
        statusEntity.setPossessionFactorKey(possessionFactorKey);
        statusEntity.setSharedSecretAlgorithm(sharedSecretAlgorithm);
        statusEntity.setTemporaryKeyActSignRequestKey(temporaryKeyActSignRequestKey);
        statusEntity.setSharedInfo2Key(sharedInfo2Key);
        statusEntity.setMacPersonalizedDataKey(macPersonalizedDataKey);
        statusEntity.setStatusBlobMacKey(statusBlobMacKey);
        statusEntity.setVersion(version);

        if (version == null || version == 3) {
            statusEntity.setTransportMasterKey(transportMasterKey);
        }

        appStatusRepository.save(statusEntity);
    }

    /**
     * Deserialize the activation status back to JSON Object.
     * @param activationId Activation ID to deserialize.
     * @return Deserialized activation status object.
     * @throws ActivationFailedException In case an activation with given ID does not exist.
     */
    public ResultStatusObject getTestStatus(String activationId) throws ActivationFailedException {
        final TestStatusEntity testStatusEntity = fetchTestStatus(activationId);

        if (testStatusEntity.getVersion() == null || testStatusEntity.getVersion() == 3) {
            return convertV3(testStatusEntity);
        }

        final ResultStatusObject result = new ResultStatusObject();
        result.setActivationId(testStatusEntity.getActivationId());
        result.setEcServerPublicKey(testStatusEntity.getEcServerPublicKey());
        result.setPqcServerPublicKey(testStatusEntity.getPqcServerPublicKey());
        result.setCounter(testStatusEntity.getCounter());
        result.setCtrData(testStatusEntity.getCtrData());
        result.setEncryptedEcDevicePrivateKey(testStatusEntity.getEncryptedEcDevicePrivateKey());
        result.setEncryptedPqcDevicePrivateKey(testStatusEntity.getEncryptedPqcDevicePrivateKey());
        result.setBiometryFactorKey(testStatusEntity.getBiometryFactorKey());
        result.setKnowledgeFactorKeyEncrypted(testStatusEntity.getKnowledgeFactorKeyEncrypted());
        result.setKnowledgeFactorKeySalt(testStatusEntity.getKnowledgeFactorKeySalt());
        result.setPossessionFactorKey(testStatusEntity.getPossessionFactorKey());
        result.setSharedSecretAlgorithm(testStatusEntity.getSharedSecretAlgorithm());
        result.setTemporaryKeyActSignRequestKey(testStatusEntity.getTemporaryKeyActSignRequestKey());
        result.setSharedInfo2Key(testStatusEntity.getSharedInfo2Key());
        result.setMacPersonalizedDataKey(testStatusEntity.getMacPersonalizedDataKey());
        result.setStatusBlobMacKey(testStatusEntity.getStatusBlobMacKey());
        result.setVersion(testStatusEntity.getVersion());
        return result;
    }

    private static ResultStatusObject convertV3(final TestStatusEntity testStatusEntity) {
        final ResultStatusObject result = new ResultStatusObject();
        result.setActivationId(testStatusEntity.getActivationId());
        result.setEcServerPublicKey(ObjectUtils.firstNonNull(testStatusEntity.getEcServerPublicKey(), testStatusEntity.getServerPublicKey()));
        result.setCounter(testStatusEntity.getCounter());
        result.setCtrData(testStatusEntity.getCtrData());
        result.setEncryptedEcDevicePrivateKey(ObjectUtils.firstNonNull(testStatusEntity.getEncryptedEcDevicePrivateKey(), testStatusEntity.getEncryptedDevicePrivateKey()));
        result.setBiometryFactorKey(ObjectUtils.firstNonNull(testStatusEntity.getBiometryFactorKey(), testStatusEntity.getSignatureBiometryKey()));
        result.setKnowledgeFactorKeyEncrypted(ObjectUtils.firstNonNull(testStatusEntity.getKnowledgeFactorKeyEncrypted(), testStatusEntity.getSignatureKnowledgeKeyEncrypted()));
        result.setKnowledgeFactorKeySalt(ObjectUtils.firstNonNull(testStatusEntity.getKnowledgeFactorKeySalt(), testStatusEntity.getSignatureKnowledgeKeySalt()));
        result.setPossessionFactorKey(ObjectUtils.firstNonNull(testStatusEntity.getPossessionFactorKey(), testStatusEntity.getSignaturePossessionKey()));
        result.setTransportMasterKey(testStatusEntity.getTransportMasterKey());
        result.setVersion(3L);
        return result;
    }

    /**
     * Increment cryptographic counter.
     * @param activationId Activation identifier.
     * @param version Protocol version.
     * @throws ActivationFailedException In case activation is not found.
     * @throws GenericCryptographyException In case counter could not be incremented.
     */
    public void incrementCounter(String activationId, PowerAuthVersion version) throws ActivationFailedException, GenericCryptographyException {
        final TestStatusEntity testStatusEntity = fetchTestStatus(activationId);

        // Increment numeric counter
        final Long counter = testStatusEntity.getCounter();
        testStatusEntity.setCounter(counter + 1);

        final String ctrDataBase64 = testStatusEntity.getCtrData();

        // Increment hash-based counter
        if (!ctrDataBase64.isEmpty()) {
            byte[] ctrData = Base64.getDecoder().decode(ctrDataBase64);
            try {
                ctrData = new HashBasedCounter(version.value()).next(ctrData);
            } catch (GenericCryptoException e) {
                throw new GenericCryptographyException(e.getMessage(), e);
            }
            testStatusEntity.setCtrData(Base64.getEncoder().encodeToString(ctrData));
        }

        appStatusRepository.save(testStatusEntity);
    }

    private TestStatusEntity fetchTestStatus(String activationId) throws ActivationFailedException {
        return appStatusRepository.findById(activationId).orElseThrow(() ->
                new ActivationFailedException("Activation with given ID not found: " + activationId));
    }
}
