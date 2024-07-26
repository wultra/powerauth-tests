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

import com.wultra.security.powerauth.app.testserver.config.TestServerConfiguration;
import com.wultra.security.powerauth.app.testserver.database.TestConfigRepository;
import com.wultra.security.powerauth.app.testserver.database.entity.TestConfigEntity;
import com.wultra.security.powerauth.app.testserver.errorhandling.ActivationFailedException;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.model.request.CreateActivationRequest;
import com.wultra.security.powerauth.app.testserver.model.response.CreateActivationResponse;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Activation service.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ActivationService extends BaseService {

    private final TestServerConfiguration config;
    private final ResultStatusService resultStatusUtil;
    private final PrepareActivationStep prepareActivationStep;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param appConfigRepository Test application configuration repository.
     * @param resultStatusUtil Result status utilities.
     * @param prepareActivationStep Prepare activation step.
     */
    @Autowired
    public ActivationService(TestServerConfiguration config, TestConfigRepository appConfigRepository, ResultStatusService resultStatusUtil, PrepareActivationStep prepareActivationStep) {
        super(appConfigRepository);
        this.config = config;
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
        final String applicationId = request.getApplicationId();
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

        final ObjectStepLogger stepLogger;
        try {
            stepLogger = new ObjectStepLogger();
            prepareActivationStep.execute(stepLogger, model.toMap());
            stepLogger.getItems()
                    .forEach(item -> StepItemLogger.log(logger, item));
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed", ex);
        }

        final String activationId = stepLogger.getItems().stream()
                .filter(item -> "Activation Done".equals(item.name()))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (String) item.get("activationId"))
                .findAny()
                .orElseThrow(() -> new ActivationFailedException("Activation failed"));

        resultStatusUtil.persistResultStatus(resultStatusObject);

        // TODO - extract response from steps
        final CreateActivationResponse response = new CreateActivationResponse();
        response.setActivationId(activationId);
        return response;
    }

}
