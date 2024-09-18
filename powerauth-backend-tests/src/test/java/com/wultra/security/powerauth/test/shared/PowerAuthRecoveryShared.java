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
package com.wultra.security.powerauth.test.shared;

import com.fasterxml.jackson.databind.JavaType;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.RecoveryCode;
import com.wultra.security.powerauth.client.model.entity.RecoveryCodePuk;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus;
import com.wultra.security.powerauth.client.model.enumeration.RecoveryPukStatus;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.RecoveryInfo;
import io.getlime.security.powerauth.crypto.lib.model.RecoverySeed;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.ActivationRecoveryStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.ConfirmRecoveryCodeStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.ActivationRecoveryStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.ConfirmRecoveryCodeStep;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationRecovery;
import io.getlime.security.powerauth.rest.api.model.exception.RecoveryError;
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer2Response;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import org.json.simple.JSONObject;

import javax.crypto.SecretKey;
import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PowerAuth recovery test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthRecoveryShared {

    private static final String PRIVATE_KEY_RECOVERY_POSTCARD_BASE64 = "ALvtO6YEISVuCKugiltkUKgJaJbHRrdT77+9OhS79Gvm";

    public static void activationRecoveryTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final File tempStatusFile, final String version) throws Exception {
        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation, assume recovery is enabled on server
        PrepareActivationStepModel prepareModel = new PrepareActivationStepModel();
        prepareModel.setActivationName("test_recovery_v" + version);
        prepareModel.setApplicationKey(config.getApplicationKey());
        prepareModel.setApplicationSecret(config.getApplicationSecret());
        prepareModel.setMasterPublicKey(config.getMasterPublicKey());
        prepareModel.setHeaders(new HashMap<>());
        prepareModel.setPassword(config.getPassword());
        prepareModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        prepareModel.setResultStatusObject(resultStatusObject);
        prepareModel.setUriString(config.getPowerAuthIntegrationUrl());
        prepareModel.setVersion(version);
        prepareModel.setActivationCode(initResponse.getActivationCode());
        prepareModel.setDeviceInfo("backend-tests");
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, prepareModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Extract recovery data
        final EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().responseObject();
        assertNotNull(eciesResponse.getEncryptedData());
        assertNotNull(eciesResponse.getMac());

        // Verify decrypted activationId
        String activationId = null;
        ActivationRecovery activationRecovery = null;
        for (StepItem item: stepLoggerPrepare.getItems()) {
            if (item.name().equals("Activation Done")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                activationId = (String) responseMap.get("activationId");
                break;
            }
            if (item.name().equals("Decrypted Layer 2 Response")) {
                activationRecovery = ((ActivationLayer2Response)item.object()).getActivationRecovery();
            }
        }

        // Verify extracted data
        assertNotNull(activationId);
        assertNotNull(activationRecovery);
        assertNotNull(activationRecovery.getRecoveryCode());
        assertNotNull(activationRecovery.getPuk());

        // Commit activation
        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status
        final GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());

        // Verify that recovery code is already confirmed
        ConfirmRecoveryCodeStepModel confirmModel = new ConfirmRecoveryCodeStepModel();
        confirmModel.setApplicationKey(config.getApplicationKey());
        confirmModel.setApplicationSecret(config.getApplicationSecret());
        confirmModel.setMasterPublicKey(config.getMasterPublicKey());
        confirmModel.setHeaders(new HashMap<>());
        confirmModel.setPassword(config.getPassword());
        confirmModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        confirmModel.setResultStatusObject(resultStatusObject);
        confirmModel.setUriString(config.getPowerAuthIntegrationUrl());
        confirmModel.setVersion(version);
        confirmModel.setRecoveryCode(activationRecovery.getRecoveryCode());

        ObjectStepLogger stepLoggerConfirm = new ObjectStepLogger(System.out);
        new ConfirmRecoveryCodeStep().execute(stepLoggerConfirm, confirmModel.toMap());
        assertTrue(stepLoggerConfirm.getResult().success());
        assertEquals(200, stepLoggerConfirm.getResponse().statusCode());

        boolean alreadyConfirmed = false;
        for (StepItem item: stepLoggerConfirm.getItems()) {
            if (item.name().equals("Recovery Code Confirmed")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                alreadyConfirmed = (boolean) responseMap.get("alreadyConfirmed");
            }
        }
        assertTrue(alreadyConfirmed);

        // Create new activation using recovery code
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("recoveryCode", activationRecovery.getRecoveryCode());
        identityAttributes.put("puk", activationRecovery.getPuk());

        ActivationRecoveryStepModel recoveryModel = new ActivationRecoveryStepModel();
        recoveryModel.setApplicationKey(config.getApplicationKey());
        recoveryModel.setApplicationSecret(config.getApplicationSecret());
        recoveryModel.setMasterPublicKey(config.getMasterPublicKey());
        recoveryModel.setHeaders(new HashMap<>());
        recoveryModel.setPassword(config.getPassword());
        recoveryModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        recoveryModel.setResultStatusObject(resultStatusObject);
        recoveryModel.setUriString(config.getPowerAuthIntegrationUrl());
        recoveryModel.setVersion(version);
        recoveryModel.setActivationName("recovery test v" + version);
        recoveryModel.setIdentityAttributes(identityAttributes);
        ObjectStepLogger stepLoggerRecovery = new ObjectStepLogger(System.out);
        new ActivationRecoveryStep().execute(stepLoggerRecovery, recoveryModel.toMap());
        assertTrue(stepLoggerRecovery.getResult().success());
        assertEquals(200, stepLoggerRecovery.getResponse().statusCode());

        // Extract activation ID
        String activationIdNew = null;
        ActivationRecovery activationRecoveryNew = null;
        for (StepItem item: stepLoggerRecovery.getItems()) {
            if (item.name().equals("Activation Done")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                activationIdNew = (String) responseMap.get("activationId");
                break;
            }
            if (item.name().equals("Decrypted Layer 2 Response")) {
                activationRecoveryNew = ((ActivationLayer2Response)item.object()).getActivationRecovery();
            }
        }

        // Verify extracted data
        assertNotNull(activationIdNew);
        assertNotEquals(activationId, activationIdNew);
        assertNotNull(activationRecoveryNew);
        assertNotNull(activationRecoveryNew.getRecoveryCode());
        assertNotNull(activationRecoveryNew.getPuk());
        assertNotEquals(activationRecovery.getRecoveryCode(), activationRecoveryNew.getRecoveryCode());

        // Verify that new activation is in ACTIVE state
        GetActivationStatusResponse statusResponseRecovered = powerAuthClient.getActivationStatus(activationIdNew);
        assertEquals(ActivationStatus.ACTIVE, statusResponseRecovered.getActivationStatus());

        // Verify that original activation is in REMOVED state
        GetActivationStatusResponse statusResponseRemoved = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.REMOVED, statusResponseRemoved.getActivationStatus());

        // Verify original recovery code and PUK status
        final LookupRecoveryCodesResponse response1 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationId, config.getApplicationId(), null, null);
        assertEquals(1, response1.getRecoveryCodes().size());
        assertEquals(RecoveryCodeStatus.REVOKED, response1.getRecoveryCodes().get(0).getStatus());
        assertEquals(1, response1.getRecoveryCodes().get(0).getPuks().size());
        assertEquals(RecoveryPukStatus.USED, response1.getRecoveryCodes().get(0).getPuks().get(0).getStatus());

        // Verify new recovery code and PUK status
        LookupRecoveryCodesResponse response2 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationIdNew, config.getApplicationId(), null, null);
        assertEquals(1, response2.getRecoveryCodes().size());
        assertEquals(RecoveryCodeStatus.ACTIVE, response2.getRecoveryCodes().get(0).getStatus());
        assertEquals(1, response2.getRecoveryCodes().get(0).getPuks().size());
        assertEquals(RecoveryPukStatus.VALID, response2.getRecoveryCodes().get(0).getPuks().get(0).getStatus());

    }

    public static void removeActivationAndRevokeRecoveryCodeTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final File tempStatusFile, final String version) throws Exception {
        for (int loop = 1; loop <= 2; loop++) {
            // We'll perform two iterations and revoke Recovery Code on activationRemove() in the second one.
            final boolean revokeRecoveryCode = loop == 2;
            final RecoveryCodeStatus expectedRecoveryCodeStatusAfterRemove = revokeRecoveryCode ? RecoveryCodeStatus.REVOKED : RecoveryCodeStatus.ACTIVE;
            final RecoveryPukStatus expectedRecoveryPukStatusAfterRemove = revokeRecoveryCode ? RecoveryPukStatus.INVALID : RecoveryPukStatus.VALID;

            final JSONObject resultStatusObject = new JSONObject();

            // Init activation
            InitActivationRequest initRequest = new InitActivationRequest();
            initRequest.setApplicationId(config.getApplicationId());
            initRequest.setUserId(config.getUser(version));
            InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

            // Prepare activation, assume recovery is enabled on server
            PrepareActivationStepModel prepareModel = new PrepareActivationStepModel();
            prepareModel.setActivationName("test_recovery_v" + version);
            prepareModel.setApplicationKey(config.getApplicationKey());
            prepareModel.setApplicationSecret(config.getApplicationSecret());
            prepareModel.setMasterPublicKey(config.getMasterPublicKey());
            prepareModel.setHeaders(new HashMap<>());
            prepareModel.setPassword(config.getPassword());
            prepareModel.setStatusFileName(tempStatusFile.getAbsolutePath());
            prepareModel.setResultStatusObject(resultStatusObject);
            prepareModel.setUriString(config.getPowerAuthIntegrationUrl());
            prepareModel.setVersion(version);
            prepareModel.setActivationCode(initResponse.getActivationCode());
            prepareModel.setDeviceInfo("backend-tests");
            ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
            new PrepareActivationStep().execute(stepLoggerPrepare, prepareModel.toMap());
            assertTrue(stepLoggerPrepare.getResult().success());
            assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

            // Extract recovery data
            final EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().responseObject();
            assertNotNull(eciesResponse.getEncryptedData());
            assertNotNull(eciesResponse.getMac());

            // Verify decrypted activationId
            String activationId = null;
            ActivationRecovery activationRecovery = null;
            for (StepItem item : stepLoggerPrepare.getItems()) {
                if (item.name().equals("Activation Done")) {
                    final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                    activationId = (String) responseMap.get("activationId");
                    break;
                }
                if (item.name().equals("Decrypted Layer 2 Response")) {
                    activationRecovery = ((ActivationLayer2Response) item.object()).getActivationRecovery();
                }
            }

            // Verify extracted data
            assertNotNull(activationId);
            assertNotNull(activationRecovery);
            assertNotNull(activationRecovery.getRecoveryCode());
            assertNotNull(activationRecovery.getPuk());

            // Commit activation
            CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
            assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

            // Verify activation status
            GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
            assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());

            // Verify recovery code and PUK status
            LookupRecoveryCodesResponse response1 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationId, config.getApplicationId(), null, null);
            assertEquals(1, response1.getRecoveryCodes().size());
            assertEquals(RecoveryCodeStatus.ACTIVE, response1.getRecoveryCodes().get(0).getStatus());
            assertEquals(1, response1.getRecoveryCodes().get(0).getPuks().size());
            assertEquals(RecoveryPukStatus.VALID, response1.getRecoveryCodes().get(0).getPuks().get(0).getStatus());

            // Remove activation
            final RemoveActivationResponse removeResponse = powerAuthClient.removeActivation(activationId, null, revokeRecoveryCode);
            assertTrue(removeResponse.isRemoved());

            // Verify recovery code and PUK status after activation remove
            LookupRecoveryCodesResponse response2 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationId, config.getApplicationId(), null, null);
            assertEquals(1, response2.getRecoveryCodes().size());
            assertEquals(expectedRecoveryCodeStatusAfterRemove, response2.getRecoveryCodes().get(0).getStatus());
            assertEquals(1, response2.getRecoveryCodes().get(0).getPuks().size());
            assertEquals(expectedRecoveryPukStatusAfterRemove, response2.getRecoveryCodes().get(0).getPuks().get(0).getStatus());
        }
    }

    public static void activationRecoveryInvalidPukTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final File tempStatusFile, final String version) throws Exception {
        final JSONObject resultStatusObject = new JSONObject();

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation, assume recovery is enabled on server
        PrepareActivationStepModel prepareModel = new PrepareActivationStepModel();
        prepareModel.setActivationName("test_recovery_invalid_puk_v" + version);
        prepareModel.setApplicationKey(config.getApplicationKey());
        prepareModel.setApplicationSecret(config.getApplicationSecret());
        prepareModel.setMasterPublicKey(config.getMasterPublicKey());
        prepareModel.setHeaders(new HashMap<>());
        prepareModel.setPassword(config.getPassword());
        prepareModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        prepareModel.setResultStatusObject(resultStatusObject);
        prepareModel.setUriString(config.getPowerAuthIntegrationUrl());
        prepareModel.setVersion(version);
        prepareModel.setActivationCode(initResponse.getActivationCode());
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, prepareModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Extract recovery data
        final EciesEncryptedResponse eciesResponse = (EciesEncryptedResponse) stepLoggerPrepare.getResponse().responseObject();
        assertNotNull(eciesResponse.getEncryptedData());
        assertNotNull(eciesResponse.getMac());

        // Verify decrypted activationId
        String activationId = null;
        ActivationRecovery activationRecovery = null;
        for (StepItem item: stepLoggerPrepare.getItems()) {
            if (item.name().equals("Activation Done")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                activationId = (String) responseMap.get("activationId");
                break;
            }
            if (item.name().equals("Decrypted Layer 2 Response")) {
                activationRecovery = ((ActivationLayer2Response)item.object()).getActivationRecovery();
            }
        }

        // Verify extracted data
        assertNotNull(activationId);
        assertNotNull(activationRecovery);
        assertNotNull(activationRecovery.getRecoveryCode());
        assertNotNull(activationRecovery.getPuk());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Verify activation status
        GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(initResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());

        // Verify recovery code and PUK status
        LookupRecoveryCodesResponse rcStatusResponse1 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationId, config.getApplicationId(), null, null);
        assertEquals(1, rcStatusResponse1.getRecoveryCodes().size());
        assertEquals(RecoveryCodeStatus.ACTIVE, rcStatusResponse1.getRecoveryCodes().get(0).getStatus());
        assertEquals(1, rcStatusResponse1.getRecoveryCodes().get(0).getPuks().size());
        assertEquals(RecoveryPukStatus.VALID, rcStatusResponse1.getRecoveryCodes().get(0).getPuks().get(0).getStatus());

        // Create new activation using recovery code with wrong PUK.
        // Assume that number of failed attempts is 5.
        final String invalidPuk = "0000000000";
        for (int i = 1; i <= 6; i++) {

            final boolean useValidPuk = i == 6;

            Map<String, String> identityAttributes = new HashMap<>();
            identityAttributes.put("recoveryCode", activationRecovery.getRecoveryCode());
            identityAttributes.put("puk", useValidPuk ? activationRecovery.getPuk() : invalidPuk);

            ActivationRecoveryStepModel recoveryModel = new ActivationRecoveryStepModel();
            recoveryModel.setApplicationKey(config.getApplicationKey());
            recoveryModel.setApplicationSecret(config.getApplicationSecret());
            recoveryModel.setMasterPublicKey(config.getMasterPublicKey());
            recoveryModel.setHeaders(new HashMap<>());
            recoveryModel.setPassword(config.getPassword());
            recoveryModel.setStatusFileName(tempStatusFile.getAbsolutePath());
            recoveryModel.setResultStatusObject(resultStatusObject);
            recoveryModel.setUriString(config.getPowerAuthIntegrationUrl());
            recoveryModel.setVersion(version);
            recoveryModel.setActivationName("recovery test v" + version);
            recoveryModel.setIdentityAttributes(identityAttributes);
            ObjectStepLogger stepLoggerRecovery = new ObjectStepLogger(System.out);
            new ActivationRecoveryStep().execute(stepLoggerRecovery, recoveryModel.toMap());

            assertFalse(stepLoggerRecovery.getResult().success());
            assertEquals(400, stepLoggerRecovery.getResponse().statusCode());
        }

        // Verify recovery code and PUK status after
        LookupRecoveryCodesResponse rcStatusResponse2 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationId, config.getApplicationId(), null, null);
        assertEquals(1, rcStatusResponse2.getRecoveryCodes().size());
        assertEquals(RecoveryCodeStatus.BLOCKED, rcStatusResponse2.getRecoveryCodes().get(0).getStatus());
        assertEquals(1, rcStatusResponse2.getRecoveryCodes().get(0).getPuks().size());
        assertEquals(RecoveryPukStatus.INVALID, rcStatusResponse2.getRecoveryCodes().get(0).getPuks().get(0).getStatus());
    }

    public static void recoveryPostcardTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final File tempStatusFile, final String version) throws Exception {
        final JSONObject resultStatusObject = new JSONObject();
        String publicKeyServerBase64 = powerAuthClient.getRecoveryConfig(config.getApplicationId()).getPostcardPublicKey();
        final String randomUserId = "TestUser_" + UUID.randomUUID();
        CreateRecoveryCodeResponse response = powerAuthClient.createRecoveryCode(config.getApplicationId(), randomUserId, 10L);

        // Verify response
        assertNotNull(response);
        assertNotNull(response.getRecoveryCodeMasked());
        assertNotNull(response.getNonce());
        assertEquals(randomUserId, response.getUserId());
        assertEquals(RecoveryCodeStatus.CREATED, response.getStatus());
        assertNotNull(response.getPuks());

        // Derive recovery code and PUKs
        KeyGenerator keyGenerator = new KeyGenerator();
        IdentifierGenerator identifierGenerator = new IdentifierGenerator();
        KeyConvertor keyConvertor = config.getKeyConvertor();
        PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(PRIVATE_KEY_RECOVERY_POSTCARD_BASE64));
        PublicKey publicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(publicKeyServerBase64));

        SecretKey secretKey = keyGenerator.computeSharedKey(privateKey, publicKey, true);

        RecoverySeed recoverySeed = new RecoverySeed();
        recoverySeed.setNonce(Base64.getDecoder().decode(response.getNonce()));
        Map<Integer, Long> pukDerivationIndexes = new HashMap<>();
        for (RecoveryCodePuk puk : response.getPuks()) {
            pukDerivationIndexes.put((int) puk.getPukIndex(), puk.getPukDerivationIndex());
        }
        recoverySeed.setPukDerivationIndexes(pukDerivationIndexes);

        RecoveryInfo recoveryInfo = identifierGenerator.deriveRecoveryCode(secretKey, recoverySeed);

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(randomUserId);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation, assume recovery is enabled on server
        PrepareActivationStepModel prepareModel = new PrepareActivationStepModel();
        prepareModel.setActivationName("test_recovery_postcard_v" + version);
        prepareModel.setApplicationKey(config.getApplicationKey());
        prepareModel.setApplicationSecret(config.getApplicationSecret());
        prepareModel.setMasterPublicKey(config.getMasterPublicKey());
        prepareModel.setHeaders(new HashMap<>());
        prepareModel.setPassword(config.getPassword());
        prepareModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        prepareModel.setResultStatusObject(resultStatusObject);
        prepareModel.setUriString(config.getPowerAuthIntegrationUrl());
        prepareModel.setVersion(version);
        prepareModel.setActivationCode(initResponse.getActivationCode());
        prepareModel.setDeviceInfo("backend-tests");
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, prepareModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Verify decrypted activationId and extract recovery data
        String activationId = null;
        ActivationRecovery activationRecovery = null;
        for (StepItem item: stepLoggerPrepare.getItems()) {
            if (item.name().equals("Activation Done")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                activationId = (String) responseMap.get("activationId");
                break;
            }
            if (item.name().equals("Decrypted Layer 2 Response")) {
                activationRecovery = ((ActivationLayer2Response)item.object()).getActivationRecovery();
            }
        }

        // Verify extracted data
        assertNotNull(activationId);
        assertNotNull(activationRecovery);
        assertNotNull(activationRecovery.getRecoveryCode());
        assertNotNull(activationRecovery.getPuk());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Confirm recovery code
        ConfirmRecoveryCodeStepModel confirmModel = new ConfirmRecoveryCodeStepModel();
        confirmModel.setApplicationKey(config.getApplicationKey());
        confirmModel.setApplicationSecret(config.getApplicationSecret());
        confirmModel.setMasterPublicKey(config.getMasterPublicKey());
        confirmModel.setHeaders(new HashMap<>());
        confirmModel.setPassword(config.getPassword());
        confirmModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        confirmModel.setResultStatusObject(resultStatusObject);
        confirmModel.setUriString(config.getPowerAuthIntegrationUrl());
        confirmModel.setVersion(version);
        confirmModel.setRecoveryCode(recoveryInfo.getRecoveryCode());

        ObjectStepLogger stepLoggerConfirm = new ObjectStepLogger(System.out);
        new ConfirmRecoveryCodeStep().execute(stepLoggerConfirm, confirmModel.toMap());
        assertTrue(stepLoggerConfirm.getResult().success());
        assertEquals(200, stepLoggerConfirm.getResponse().statusCode());

        Boolean alreadyConfirmed = null;
        for (StepItem item: stepLoggerConfirm.getItems()) {
            if (item.name().equals("Recovery Code Confirmed")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                alreadyConfirmed = (boolean) responseMap.get("alreadyConfirmed");
            }
        }
        assertNotNull(alreadyConfirmed);
        assertFalse(alreadyConfirmed);

        // Create new activation using recovery code
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("recoveryCode", recoveryInfo.getRecoveryCode());
        identityAttributes.put("puk", recoveryInfo.getPuks().get(1));

        ActivationRecoveryStepModel recoveryModel = new ActivationRecoveryStepModel();
        recoveryModel.setApplicationKey(config.getApplicationKey());
        recoveryModel.setApplicationSecret(config.getApplicationSecret());
        recoveryModel.setMasterPublicKey(config.getMasterPublicKey());
        recoveryModel.setHeaders(new HashMap<>());
        recoveryModel.setPassword(config.getPassword());
        recoveryModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        recoveryModel.setResultStatusObject(resultStatusObject);
        recoveryModel.setUriString(config.getPowerAuthIntegrationUrl());
        recoveryModel.setVersion(version);
        recoveryModel.setActivationName("recovery postcard test v" + version);
        recoveryModel.setIdentityAttributes(identityAttributes);
        ObjectStepLogger stepLoggerRecovery = new ObjectStepLogger(System.out);
        new ActivationRecoveryStep().execute(stepLoggerRecovery, recoveryModel.toMap());
        assertTrue(stepLoggerRecovery.getResult().success());
        assertEquals(200, stepLoggerRecovery.getResponse().statusCode());

        // Extract activation ID
        String activationIdNew = null;
        ActivationRecovery activationRecoveryNew = null;
        for (StepItem item: stepLoggerRecovery.getItems()) {
            if (item.name().equals("Activation Done")) {
                final Map<String, Object> responseMap = (Map<String, Object>) item.object();
                activationIdNew = (String) responseMap.get("activationId");
                break;
            }
            if (item.name().equals("Decrypted Layer 2 Response")) {
                activationRecoveryNew = ((ActivationLayer2Response)item.object()).getActivationRecovery();
            }
        }

        // Verify extracted data
        assertNotNull(activationIdNew);
        assertNotEquals(activationId, activationIdNew);
        assertNotNull(activationRecoveryNew);
        assertNotNull(activationRecoveryNew.getRecoveryCode());
        assertNotNull(activationRecoveryNew.getPuk());
        assertNotEquals(recoveryInfo.getRecoveryCode(), activationRecoveryNew.getRecoveryCode());

        // Verify that new activation is in ACTIVE state
        GetActivationStatusResponse statusResponseRecovered = powerAuthClient.getActivationStatus(activationIdNew);
        assertEquals(ActivationStatus.ACTIVE, statusResponseRecovered.getActivationStatus());

        // Verify that original activation remains ACTIVE - recovery activation for postcard does not remove original activation
         GetActivationStatusResponse statusResponseRemoved = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.ACTIVE, statusResponseRemoved.getActivationStatus());

        // Verify postcard recovery code and PUK status
        LookupRecoveryCodesResponse responsePostcard = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), null, config.getApplicationId(), null, null);
        assertEquals(3, responsePostcard.getRecoveryCodes().size());
        for (int i = 0; i < 3; i++) {
            final RecoveryCode postcardRecoveryCode = responsePostcard.getRecoveryCodes().get(i);
            if (postcardRecoveryCode.getActivationId() != null) {
                continue;
            }
            assertEquals(RecoveryCodeStatus.ACTIVE, postcardRecoveryCode.getStatus());
            assertEquals(10, postcardRecoveryCode.getPuks().size());
            assertEquals(RecoveryPukStatus.USED, postcardRecoveryCode.getPuks().get(0).getStatus());
            for (int j = 1; j < 10; j++) {
                assertEquals(RecoveryPukStatus.VALID, postcardRecoveryCode.getPuks().get(j).getStatus());
            }
        }

        // Verify old activation recovery code and PUK status
        LookupRecoveryCodesResponse response1 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationId, config.getApplicationId(), null, null);
        assertEquals(1, response1.getRecoveryCodes().size());
        assertEquals(RecoveryCodeStatus.ACTIVE, response1.getRecoveryCodes().get(0).getStatus());
        assertEquals(1, response1.getRecoveryCodes().get(0).getPuks().size());
        assertEquals(RecoveryPukStatus.VALID, response1.getRecoveryCodes().get(0).getPuks().get(0).getStatus());

        // Verify new activation recovery code and PUK status
        LookupRecoveryCodesResponse response2 = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), activationIdNew, config.getApplicationId(), null, null);
        assertEquals(1, response2.getRecoveryCodes().size());
        assertEquals(RecoveryCodeStatus.ACTIVE, response2.getRecoveryCodes().get(0).getStatus());
        assertEquals(1, response2.getRecoveryCodes().get(0).getPuks().size());
        assertEquals(RecoveryPukStatus.VALID, response2.getRecoveryCodes().get(0).getPuks().get(0).getStatus());
    }

    public static void recoveryPostcardInvalidPukIndexTest(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final File tempStatusFile, String version) throws Exception {
        final JSONObject resultStatusObject = new JSONObject();
        String publicKeyServerBase64 = powerAuthClient.getRecoveryConfig(config.getApplicationId()).getPostcardPublicKey();
        final String randomUserId = "TestUser_" + UUID.randomUUID();
        CreateRecoveryCodeResponse response = powerAuthClient.createRecoveryCode(config.getApplicationId(), randomUserId, 10L);

        // Derive recovery code and PUKs
        KeyGenerator keyGenerator = new KeyGenerator();
        IdentifierGenerator identifierGenerator = new IdentifierGenerator();
        KeyConvertor keyConvertor = config.getKeyConvertor();
        PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(PRIVATE_KEY_RECOVERY_POSTCARD_BASE64));
        PublicKey publicKey = keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(publicKeyServerBase64));
        SecretKey secretKey = keyGenerator.computeSharedKey(privateKey, publicKey, true);

        RecoverySeed recoverySeed = new RecoverySeed();
        recoverySeed.setNonce(Base64.getDecoder().decode(response.getNonce()));
        Map<Integer, Long> pukDerivationIndexes = new HashMap<>();
        for (RecoveryCodePuk puk : response.getPuks()) {
            pukDerivationIndexes.put((int) puk.getPukIndex(), puk.getPukDerivationIndex());
        }
        recoverySeed.setPukDerivationIndexes(pukDerivationIndexes);

        RecoveryInfo recoveryInfo = identifierGenerator.deriveRecoveryCode(secretKey, recoverySeed);

        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(randomUserId);
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation, assume recovery is enabled on server
        PrepareActivationStepModel prepareModel = new PrepareActivationStepModel();
        prepareModel.setActivationName("test_recovery_postcard_v" + version);
        prepareModel.setApplicationKey(config.getApplicationKey());
        prepareModel.setApplicationSecret(config.getApplicationSecret());
        prepareModel.setMasterPublicKey(config.getMasterPublicKey());
        prepareModel.setHeaders(new HashMap<>());
        prepareModel.setPassword(config.getPassword());
        prepareModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        prepareModel.setResultStatusObject(resultStatusObject);
        prepareModel.setUriString(config.getPowerAuthIntegrationUrl());
        prepareModel.setVersion(version);
        prepareModel.setActivationCode(initResponse.getActivationCode());
        prepareModel.setDeviceInfo("backend-tests");
        ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, prepareModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().success());
        assertEquals(200, stepLoggerPrepare.getResponse().statusCode());

        // Extract recovery data
        ActivationRecovery activationRecovery = null;
        for (StepItem item: stepLoggerPrepare.getItems()) {
            if (item.name().equals("Decrypted Layer 2 Response")) {
                activationRecovery = ((ActivationLayer2Response)item.object()).getActivationRecovery();
            }
        }

        // Verify extracted data
        assertNotNull(activationRecovery);
        assertNotNull(activationRecovery.getRecoveryCode());
        assertNotNull(activationRecovery.getPuk());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        // Confirm recovery code
        ConfirmRecoveryCodeStepModel confirmModel = new ConfirmRecoveryCodeStepModel();
        confirmModel.setApplicationKey(config.getApplicationKey());
        confirmModel.setApplicationSecret(config.getApplicationSecret());
        confirmModel.setMasterPublicKey(config.getMasterPublicKey());
        confirmModel.setHeaders(new HashMap<>());
        confirmModel.setPassword(config.getPassword());
        confirmModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        confirmModel.setResultStatusObject(resultStatusObject);
        confirmModel.setUriString(config.getPowerAuthIntegrationUrl());
        confirmModel.setVersion(version);
        confirmModel.setRecoveryCode(recoveryInfo.getRecoveryCode());

        ObjectStepLogger stepLoggerConfirm = new ObjectStepLogger(System.out);
        new ConfirmRecoveryCodeStep().execute(stepLoggerConfirm, confirmModel.toMap());
        assertTrue(stepLoggerConfirm.getResult().success());
        assertEquals(200, stepLoggerConfirm.getResponse().statusCode());

        // Create new activation using recovery code
        Map<String, String> identityAttributes = new HashMap<>();
        identityAttributes.put("recoveryCode", recoveryInfo.getRecoveryCode());
        // Use valid PUK
        identityAttributes.put("puk", recoveryInfo.getPuks().get(1));

        ActivationRecoveryStepModel recoveryModel = new ActivationRecoveryStepModel();
        recoveryModel.setApplicationKey(config.getApplicationKey());
        recoveryModel.setApplicationSecret(config.getApplicationSecret());
        recoveryModel.setMasterPublicKey(config.getMasterPublicKey());
        recoveryModel.setHeaders(new HashMap<>());
        recoveryModel.setPassword(config.getPassword());
        recoveryModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        recoveryModel.setResultStatusObject(resultStatusObject);
        recoveryModel.setUriString(config.getPowerAuthIntegrationUrl());
        recoveryModel.setVersion(version);
        recoveryModel.setActivationName("recovery postcard test valid PUK v" + version);
        recoveryModel.setIdentityAttributes(identityAttributes);
        ObjectStepLogger stepLoggerRecovery = new ObjectStepLogger(System.out);
        new ActivationRecoveryStep().execute(stepLoggerRecovery, recoveryModel.toMap());
        assertTrue(stepLoggerRecovery.getResult().success());
        assertEquals(200, stepLoggerRecovery.getResponse().statusCode());

        // Use invalid PUK
        recoveryModel.setActivationName("recovery postcard test invalid PUK v" + version);
        ObjectStepLogger stepLoggerRecovery2 = new ObjectStepLogger(System.out);
        new ActivationRecoveryStep().execute(stepLoggerRecovery2, recoveryModel.toMap());
        assertFalse(stepLoggerRecovery2.getResult().success());
        assertEquals(400, stepLoggerRecovery2.getResponse().statusCode());

        // Extract error
        Integer currentRecoveryPukIndex = null;
        for (StepItem item: stepLoggerRecovery2.getItems()) {
            if (item.name().equals("Response 400 - ERROR")) {
                final String recoveryErrorJSON = (String) ((HashMap)item.object()).get("responseObject");
                JavaType type = config.getObjectMapper().getTypeFactory().constructParametricType(ObjectResponse.class, RecoveryError.class);
                ObjectResponse<RecoveryError> recoveryError = config.getObjectMapper().readValue(recoveryErrorJSON, type);
                currentRecoveryPukIndex = recoveryError.getResponseObject().getCurrentRecoveryPukIndex();
            }
        }

        assertNotNull(currentRecoveryPukIndex);
        assertEquals(2L, (long)currentRecoveryPukIndex);

        // Use correct PUK now
        identityAttributes.put("puk", recoveryInfo.getPuks().get(currentRecoveryPukIndex));

        recoveryModel.setActivationName("recovery postcard test valid PUK 2 v" + version);
        ObjectStepLogger stepLoggerRecovery3 = new ObjectStepLogger(System.out);
        new ActivationRecoveryStep().execute(stepLoggerRecovery3, recoveryModel.toMap());
        assertTrue(stepLoggerRecovery3.getResult().success());
        assertEquals(200, stepLoggerRecovery3.getResponse().statusCode());

        // Verify postcard recovery code and PUK status
        LookupRecoveryCodesResponse responseCode = powerAuthClient.lookupRecoveryCodes(initResponse.getUserId(), null, config.getApplicationId(), null, null);
        assertEquals(4, responseCode.getRecoveryCodes().size());
        for (int i = 0; i < 4; i++) {
            final RecoveryCode postcardRecoveryCode = responseCode.getRecoveryCodes().get(i);
            if (postcardRecoveryCode.getActivationId() != null) {
                continue;
            }
            assertEquals(RecoveryCodeStatus.ACTIVE, postcardRecoveryCode.getStatus());
            assertEquals(10, postcardRecoveryCode.getPuks().size());
            assertEquals(RecoveryPukStatus.USED, postcardRecoveryCode.getPuks().get(0).getStatus());
            assertEquals(RecoveryPukStatus.USED, postcardRecoveryCode.getPuks().get(1).getStatus());
            for (int j = 2; j < 10; j++) {
                assertEquals(RecoveryPukStatus.VALID, postcardRecoveryCode.getPuks().get(j).getStatus());
            }
        }
    }

    // TODO - revoke test

    // TODO - negative tests for postcards

}
