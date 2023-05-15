/*
 * PowerAuth test and related software components
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
package com.wultra.security.powerauth.test;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.Application;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.UpdateRecoveryConfigRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Arrays;
import java.util.HashMap;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Global test setup.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthTestSetUp {

    private static final String PUBLIC_KEY_RECOVERY_POSTCARD_BASE64 = "BABXgGoj4Lizl3GN0rjrtileEEwekFkpX1ERS9yyYjyuM1Iqdti3ihtATBxk5XGvjetPO1YC+qXciUYjIsETtbI=";

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    public void execute() throws Exception {
        createApplication();
        createActivationV31();
        createActivationV3();
        createOperationTemplates();
    }

    private void createOperationTemplates() throws Exception {
        createLoginOperationTemplate();
    }

    private void createLoginOperationTemplate() throws Exception {
        final OperationTemplateCreateRequest request = new OperationTemplateCreateRequest();
        request.setTemplateName(UUID.randomUUID().toString());
        request.setOperationType("login");
        request.getSignatureType().addAll(Arrays.asList(SignatureType.values()));
        request.setDataTemplate("A2");
        request.setExpiration(300L);
        request.setMaxFailureCount(5L);

        final OperationTemplateDetailResponse operationTemplate = powerAuthClient.createOperationTemplate(request);
        config.setLoginOperationTemplateName(operationTemplate.getTemplateName());
        config.setLoginOperationTemplateId(operationTemplate.getId());
    }

    private void createApplication() throws PowerAuthClientException {
        // Create application if it does not exist
        final GetApplicationListResponse applicationsListResponse = powerAuthClient.getApplicationList();
        boolean applicationExists = false;
        for (Application app: applicationsListResponse.getApplications()) {
            if (app.getApplicationId().equals(config.getApplicationName())) {
                applicationExists = true;
                config.setApplicationId(app.getApplicationId());
            }
        }
        if (!applicationExists) {
            final CreateApplicationResponse response = powerAuthClient.createApplication(config.getApplicationName());
            assertNotEquals(0, response.getApplicationId());
            assertEquals(config.getApplicationName(), response.getApplicationId());
            config.setApplicationId(response.getApplicationId());
        }


        // Create application version if it does not exist
        final GetApplicationDetailResponse detail = powerAuthClient.getApplicationDetail(config.getApplicationId());
        boolean versionExists = false;
        for (ApplicationVersion appVersion: detail.getVersions()) {
            if (appVersion.getApplicationVersionId().equals(config.getApplicationVersion())) {
                versionExists = true;
                config.setApplicationVersionId(appVersion.getApplicationVersionId());
                config.setApplicationKey(appVersion.getApplicationKey());
                config.setApplicationSecret(appVersion.getApplicationSecret());
            }
        }
        config.setMasterPublicKey(detail.getMasterPublicKey());
        if (!versionExists) {
            final CreateApplicationVersionResponse versionResponse = powerAuthClient.createApplicationVersion(config.getApplicationId(), config.getApplicationVersion());
            assertNotEquals(0, versionResponse.getApplicationVersionId());
            assertEquals(config.getApplicationVersion(), versionResponse.getApplicationVersionId());
            config.setApplicationVersionId(versionResponse.getApplicationVersionId());
            config.setApplicationKey(versionResponse.getApplicationKey());
            config.setApplicationSecret(versionResponse.getApplicationSecret());
        } else {
            // Make sure application version is supported
            powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());
        }
        // Set up activation recovery
        final GetRecoveryConfigResponse recoveryResponse = powerAuthClient.getRecoveryConfig(config.getApplicationId());
        if (!recoveryResponse.isActivationRecoveryEnabled() || !recoveryResponse.isRecoveryPostcardEnabled() || recoveryResponse.getPostcardPublicKey() == null || recoveryResponse.getRemotePostcardPublicKey() == null) {
            final UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
            request.setApplicationId(config.getApplicationId());
            request.setActivationRecoveryEnabled(true);
            request.setRecoveryPostcardEnabled(true);
            request.setAllowMultipleRecoveryCodes(false);
            request.setRemotePostcardPublicKey(PUBLIC_KEY_RECOVERY_POSTCARD_BASE64);
            powerAuthClient.updateRecoveryConfig(request);
        }
    }

    private void createActivationV31() throws Exception {
        // Init activation
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV31());
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationCode(initResponse.getActivationCode());
        model.setActivationName("test v31");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(config.getStatusFileV31().getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObjectV31());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.1");
        model.setDeviceInfo("backend-tests");

        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        config.setActivationIdV31(initResponse.getActivationId());
    }

    private void createActivationV3() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUserV3());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationCode(initResponse.getActivationCode());
        model.setActivationName("test v3");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(config.getStatusFileV3().getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObjectV3());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion("3.0");
        model.setDeviceInfo("backend-tests");

        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        config.setActivationIdV3(initResponse.getActivationId());
    }

}
