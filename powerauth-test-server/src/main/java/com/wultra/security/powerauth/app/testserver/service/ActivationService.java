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

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.app.testserver.config.TestServerConfiguration;
import com.wultra.security.powerauth.app.testserver.database.TestConfigRepository;
import com.wultra.security.powerauth.app.testserver.database.entity.TestConfigEntity;
import com.wultra.security.powerauth.app.testserver.errorhandling.ActivationFailedException;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.model.request.CreateActivationRequest;
import com.wultra.security.powerauth.app.testserver.model.response.CreateActivationResponse;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Activation service.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class ActivationService {

    private final static Logger logger = LoggerFactory.getLogger(ActivationService.class);

    private final TestServerConfiguration config;
    private final TestConfigRepository appConfigRepository;
    private final ResultStatusService resultStatusUtil;
    private final PrepareActivationStep prepareActivationStep;

    private static final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param configRepository Test application configuration repository.
     * @param resultStatusUtil Result status utilities.
     * @param prepareActivationStep Prepare activation step.
     */
    @Autowired
    public ActivationService(TestServerConfiguration config, TestConfigRepository configRepository, ResultStatusService resultStatusUtil, PrepareActivationStep prepareActivationStep) {
        this.config = config;
        this.appConfigRepository = configRepository;
        this.resultStatusUtil = resultStatusUtil;
        this.prepareActivationStep = prepareActivationStep;
    }

    /**
     * Create an activation using activation code.
     * @param request Create activation request.
     * @return Create activation response.
     * @throws AppConfigNotFoundException Thrown when application configuration is not found.
     * @throws GenericCryptographyException Thrown when cryptography computation fails.
     */
    @Transactional
    @SuppressWarnings("unchecked")
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws AppConfigNotFoundException, GenericCryptographyException, RemoteExecutionException, ActivationFailedException {
        // TODO - input validation
        final Long applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final PublicKey publicKey = getMasterPublicKey(appConfig);
        final JSONObject resultStatusObject = new JSONObject();

        // Prepare activation
        final PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationCode(request.getActivationCode());
        model.setActivationName(request.getActivationName());
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setMasterPublicKey(publicKey);
        model.setHeaders(new HashMap<>());
        model.setPassword(request.getPassword());
        model.setResultStatusObject(resultStatusObject);
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setVersion(config.getVersion());
        model.setDeviceInfo("backend-tests");

        String activationId = null;
        try {
            final ObjectStepLogger stepLogger = new ObjectStepLogger();
            prepareActivationStep.execute(stepLogger, model.toMap());
            for (StepItem item: stepLogger.getItems()) {
                if ("Activation Done".equals(item.getName())) {
                    final Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                    activationId = (String) responseMap.get("activationId");
                    break;
                }
            }
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed");
        }

        if (activationId == null) {
            logger.warn("Activation failed");
            throw new ActivationFailedException("Activation failed");
        }

        resultStatusUtil.persistResultStatus(resultStatusObject);

        // TODO - extract response from steps
        final CreateActivationResponse response = new CreateActivationResponse();
        response.setActivationId(activationId);
        return response;
    }

    /**
     * Get test application configuration.
     * @param applicationId Application identifier.
     * @return Test application configuration.
     * @throws AppConfigNotFoundException Thrown when application configuration is not found.
     */
    private TestConfigEntity getTestAppConfig(Long applicationId) throws AppConfigNotFoundException {
        final Optional<TestConfigEntity> appConfigOptional = appConfigRepository.findById(applicationId);

        if (appConfigOptional.isEmpty()) {
            throw new AppConfigNotFoundException("Application configuration was not found for application ID: " + applicationId);
        }

        return appConfigOptional.get();
    }

    /**
     * Get master public key from test application configuration.
     * @param appConfig Test application configuration.
     * @return Master public key.
     * @throws GenericCryptographyException Thrown in case public key conversion fails.
     */
    private PublicKey getMasterPublicKey(TestConfigEntity appConfig) throws GenericCryptographyException {
        final byte[] masterKeyBytes = BaseEncoding.base64().decode(appConfig.getMasterPublicKey());

        try {
            return keyConvertor.convertBytesToPublicKey(masterKeyBytes);
        } catch (Exception ex) {
            logger.warn("Key conversion failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new GenericCryptographyException("Key conversion failed");
        }
    }
}
