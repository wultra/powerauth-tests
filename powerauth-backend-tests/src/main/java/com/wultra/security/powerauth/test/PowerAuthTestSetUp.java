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

import com.wultra.security.powerauth.client.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.CreateApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.model.response.v4.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.Application;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfiguration;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfigurationException;
import com.wultra.security.powerauth.crypto.lib.sdk.SdkConfigurationSerializer;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.ConfirmActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.ConfirmActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Global test setup.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthTestSetUp {

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
        PowerAuthVersion.ALL_VERSIONS.forEach(version -> {
            try {
                createActivation(version);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        createOperationTemplates();
    }

    private void createOperationTemplates() throws Exception {
        createLoginOperationTemplate();
    }

    private void createLoginOperationTemplate() throws Exception {
        final OperationTemplateCreateRequest request = new OperationTemplateCreateRequest();
        request.setTemplateName(UUID.randomUUID().toString());
        request.setOperationType("login");
        request.getAuthenticationCodeType().addAll(Arrays.asList(AuthenticationCodeType.values()));
        request.setDataTemplate("A2");
        request.setExpiration(300L);
        request.setMaxFailureCount(5L);

        final OperationTemplateDetailResponse operationTemplate = powerAuthClient.createOperationTemplate(request);
        config.setLoginOperationTemplateName(operationTemplate.getTemplateName());
        config.setLoginOperationTemplateId(operationTemplate.getId());
    }

    private void createApplication() throws PowerAuthClientException, SdkConfigurationException {
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
            assertNotEquals("0", response.getApplicationId());
            assertEquals(config.getApplicationName(), response.getApplicationId());
            config.setApplicationId(response.getApplicationId());
        }

        // Configure activation transfer
        CreateApplicationConfigRequest configRequest = new CreateApplicationConfigRequest();
        configRequest.setApplicationId(config.getApplicationId());
        configRequest.setKey("activation_transfer");
        ActivationTransferConfiguration transferConfig = new ActivationTransferConfiguration(List.of("PA_Tests"), ActivationTransferType.SPAWN, null);
        configRequest.setValues(List.of(transferConfig));
        powerAuthClient.createApplicationConfig(configRequest);


        // Create application version if it does not exist
        final GetApplicationDetailResponse detail = powerAuthClient.getApplicationDetail(config.getApplicationId());
        ApplicationVersion resolvedAppVersion = null;
        for (ApplicationVersion appVersion: detail.getVersions()) {
            if (appVersion.getApplicationVersionId().equals(config.getApplicationVersion())) {
                resolvedAppVersion = appVersion;
            }
        }
        if (resolvedAppVersion == null) {
            final CreateApplicationVersionResponse versionResponse = powerAuthClient.createApplicationVersion(config.getApplicationId(), config.getApplicationVersion());
            assertNotEquals("0", versionResponse.getApplicationVersionId());
            assertEquals(config.getApplicationVersion(), versionResponse.getApplicationVersionId());
            config.setApplicationVersionId(versionResponse.getApplicationVersionId());
            config.setApplicationKey(versionResponse.getApplicationKey());
            config.setApplicationSecret(versionResponse.getApplicationSecret());
            final GetApplicationDetailResponse applicationDetail = powerAuthClient.getApplicationDetail(config.getApplicationId());
            for (ApplicationVersion appVersion: applicationDetail.getVersions()) {
                if (appVersion.getApplicationVersionId().equals(config.getApplicationVersion())) {
                    resolvedAppVersion = appVersion;
                }
            }
        } else {
            // Make sure application version is supported
            powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());
        }

        final SdkConfiguration sdkConfiguration = SdkConfigurationSerializer.deserialize(resolvedAppVersion.getMobileSdkConfig());
        config.setApplicationVersionId(resolvedAppVersion.getApplicationVersionId());
        config.setApplicationKey(resolvedAppVersion.getApplicationKey());
        config.setApplicationSecret(resolvedAppVersion.getApplicationSecret());
        config.setMasterPublicKeyP256(sdkConfiguration.masterPublicKeyP256());
        config.setMasterPublicKeyP384(sdkConfiguration.masterPublicKeyP384());
        config.setMasterPublicKeyMlDsa65(sdkConfiguration.masterPublicKeyMlDsa65());
        config.setMasterPublicKeyMlDsa87(sdkConfiguration.masterPublicKeyMlDsa87());
    }

    private void createActivation(PowerAuthVersion version) throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser(version));
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationCode(initResponse.getActivationCode());
        model.setActivationName("test v" + version);
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKeyP256(config.getMasterPublicKeyP256());
        if (version.getMajorVersion() > 3) {
            model.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
            model.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
            model.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        }
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(config.getStatusFile(version).getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObject(version));
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion(version);
        model.setDeviceInfo("backend-tests");

        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());

        // Confirm v4 activations to enable biometry
        if (version.getMajorVersion() > 3) {
            ConfirmActivationStepModel confirmModel = new ConfirmActivationStepModel();
            confirmModel.setApplicationKey(config.getApplicationKey());
            confirmModel.setApplicationSecret(config.getApplicationSecret());
            confirmModel.setEnableBiometry(true);
            confirmModel.setPassword(config.getPassword());
            confirmModel.setVersion(version);
            confirmModel.setStatusFileName(config.getStatusFile(version).getAbsolutePath());
            confirmModel.setResultStatusObject(config.getResultStatusObject(version));
            confirmModel.setUriString(config.getPowerAuthIntegrationUrl());
            ObjectStepLogger stepLoggerConfirm = new ObjectStepLogger(System.out);
            new ConfirmActivationStep().execute(stepLoggerConfirm, confirmModel.toMap());
            assertTrue(stepLoggerConfirm.getResult().success());
        }

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());

        config.setActivationId(initResponse.getActivationId(), version);
    }

    private record ActivationTransferConfiguration(List<String> allowedTargetApplicationIds, ActivationTransferType type, List<String> initialFlags) {}

}
