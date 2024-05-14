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
import com.wultra.security.powerauth.app.testserver.model.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeTokenDigestRequest;
import com.wultra.security.powerauth.app.testserver.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeTokenDigestResponse;
import com.wultra.security.powerauth.app.testserver.model.response.CreateTokenResponse;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.VerifyTokenStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateTokenStep;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

/**
 * Service for working with PowerAuth tokens.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class TokenService extends BaseService {

    private final TestServerConfiguration config;
    private final ResultStatusService resultStatusUtil;
    private final CreateTokenStep createTokenStep;
    private final VerifyTokenStep verifyTokenStep;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param resultStatusUtil Result status utilities.
     * @param createTokenStep Create token step.
     * @param verifyTokenStep Verify token step.
     */
    @Autowired
    public TokenService(TestServerConfiguration config, TestConfigRepository appConfigRepository, ResultStatusService resultStatusUtil, CreateTokenStep createTokenStep, VerifyTokenStep verifyTokenStep) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.createTokenStep = createTokenStep;
        this.verifyTokenStep = verifyTokenStep;
    }

    /**
     * Create a new token.
     * @param request Request for creating a new token.
     * @return Response with a created token.
     * @throws GenericCryptographyException In case a crypto provider is not initialized properly.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws AppConfigNotFoundException In case app configuration is incorrect.
     * @throws ActivationFailedException In case activation is not found.
     */
    @Transactional
    @SuppressWarnings("unchecked")
    public CreateTokenResponse createToken(CreateTokenRequest request) throws AppConfigNotFoundException, GenericCryptographyException, RemoteExecutionException, ActivationFailedException {

        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final PublicKey publicKey = getMasterPublicKey(appConfig);
        final JSONObject resultStatusObject = resultStatusUtil.getTestStatus(request.getActivationId());
        PowerAuthSignatureTypes signatureType = SignatureTypeConverter.convert(request.getSignatureType());
        if (signatureType == null) {
            // Fallback to previous behavior when there was no signatureType property in the request.
            signatureType = PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE;
        }
        final CreateTokenStepModel model = new CreateTokenStepModel();
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setPassword(request.getPassword());
        model.setMasterPublicKey(publicKey);
        model.setSignatureType(signatureType);
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatusObject(resultStatusObject);

        final ObjectStepLogger stepLogger;
        try {
            stepLogger = new ObjectStepLogger();
            createTokenStep.execute(stepLogger, model.toMap());
            stepLogger.getItems()
                    .forEach(item -> StepItemLogger.log(logger, item));
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed", ex);
        }

        resultStatusUtil.persistResultStatus(resultStatusObject);

        final Map<String, Object> responseMap = stepLogger.getItems().stream()
                .filter(item -> "Token successfully obtained".equals(item.name()))
                .map(item -> (Map<String, Object>) item.object())
                .findAny()
                .orElse(Collections.emptyMap());

        final String tokenId = (String) responseMap.get("tokenId");
        final String tokenSecret = (String) responseMap.get("tokenSecret");

        final CreateTokenResponse result = new CreateTokenResponse();
        result.setTokenId(tokenId);
        result.setTokenSecret(tokenSecret);
        return result;
    }

    /**
     * Compute a token digest.
     * @param request Request for computing a token digest.
     * @return Response for computing a token digest.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     */
    @SuppressWarnings("unchecked")
    public ComputeTokenDigestResponse computeTokenDigest(ComputeTokenDigestRequest request) throws RemoteExecutionException, ActivationFailedException {

        final JSONObject resultStatusObject = resultStatusUtil.getTestStatus(request.getActivationId());

        final VerifyTokenStepModel model = new VerifyTokenStepModel();
        model.setTokenId(request.getTokenId());
        model.setTokenSecret(request.getTokenSecret());
        model.setHttpMethod("POST");
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatusObject(resultStatusObject);
        model.setDryRun(true);

        final ObjectStepLogger stepLogger;
        try {
            stepLogger = new ObjectStepLogger();
            verifyTokenStep.execute(stepLogger, model.toMap());
            stepLogger.getItems()
                    .forEach(item -> StepItemLogger.log(logger, item));
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed", ex);
        }

        final String authHeader = stepLogger.getItems().stream()
                .filter(item -> "token-validate-request-sent".equals(item.id()))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (Map<String, Object>) item.get("requestHeaders"))
                .map(item -> item.get("X-PowerAuth-Token").toString())
                .findAny()
                .orElse(null);

        final ComputeTokenDigestResponse response = new ComputeTokenDigestResponse();
        response.setAuthHeader(authHeader);
        return response;
    }

}
