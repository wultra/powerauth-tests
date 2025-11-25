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
import com.wultra.security.powerauth.app.testserver.model.converter.AuthenticationCodeTypeConverter;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeOfflineAuthRequest;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeOnlineAuthRequest;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeOfflineAuthResponse;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeOnlineAuthResponse;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import com.wultra.security.powerauth.app.testserver.util.VersionCheckService;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.ComputeOfflineAuthenticationStep;
import com.wultra.security.powerauth.lib.cmd.steps.VerifyAuthenticationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.ComputeOfflineAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Service for calculating PowerAuth signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class AuthenticationService extends BaseService {

    private final TestServerConfiguration config;
    private final ResultStatusService resultStatusUtil;
    private final VerifyAuthenticationStep VerifyAuthenticationStep;
    private final ComputeOfflineAuthenticationStep computeOfflineSignatureStep;
    private final VersionCheckService versionCheckService;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param appConfigRepository Test application configuration repository.
     * @param resultStatusUtil Result status utilities.
     * @param verifyAuthenticationStep Verify signature step.
     * @param computeOfflineSignatureStep Compute offline signature step.
     * @param versionCheckService Version check service.
     */
    @Autowired
    public AuthenticationService(TestServerConfiguration config, TestConfigRepository appConfigRepository, ResultStatusService resultStatusUtil, VerifyAuthenticationStep verifyAuthenticationStep, ComputeOfflineAuthenticationStep computeOfflineSignatureStep, VersionCheckService versionCheckService) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.VerifyAuthenticationStep = verifyAuthenticationStep;
        this.computeOfflineSignatureStep = computeOfflineSignatureStep;
        this.versionCheckService = versionCheckService;
    }

    /**
     * Compute an online signature.
     * @param request Request for computing an online signature.
     * @return Response for computing an online signature.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws AppConfigNotFoundException In case application configuration is not found.
     * @throws GenericCryptographyException In case of a cryptography error.
     */
    public ComputeOnlineAuthResponse computeOnlineAuth(ComputeOnlineAuthRequest request) throws RemoteExecutionException, ActivationFailedException, AppConfigNotFoundException, GenericCryptographyException {

        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final ResultStatusObject resultStatus = resultStatusUtil.getTestStatus(request.getActivationId());

        versionCheckService.checkVersion(resultStatus);

        final VerifyAuthenticationStepModel model = new VerifyAuthenticationStepModel();
        model.setHttpMethod(request.getHttpMethod());
        model.setResourceId(request.getResourceId());
        model.setAuthenticationCodeType(AuthenticationCodeTypeConverter.convert(request.getAuthenticationCodeType() != null
                ? request.getAuthenticationCodeType()
                : request.getSignatureType()));
        if (request.getRequestBody() != null) {
            model.setData(Base64.getDecoder().decode(request.getRequestBody()));
        }
        model.setPassword(request.getPassword());
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatus(resultStatus);
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setDryRun(true);

        final ObjectStepLogger stepLogger;
        try {
            stepLogger = new ObjectStepLogger();
            VerifyAuthenticationStep.execute(stepLogger, model.toMap());
            stepLogger.getItems()
                    .forEach(item -> StepItemLogger.log(logger, item));
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed", ex);
        }

        final Optional<String> authHeader = stepLogger.getItems().stream()
                .filter(item -> "signature-verify-request-sent".equals(item.id()))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (Map<String, Object>) item.get("requestHeaders"))
                .map(item -> item.get("X-PowerAuth-Authorization").toString())
                .findAny();

        if (authHeader.isPresent()) {
            resultStatusUtil.incrementCounter(request.getActivationId(), PowerAuthVersion.fromValue(config.getVersion()));
        }

        final ComputeOnlineAuthResponse response = new ComputeOnlineAuthResponse();
        response.setAuthHeader(authHeader.orElse(null));
        return response;
    }

    /**
     * Compute an offline signature.
     * @param request Request for computing an offline signature.
     * @return Response for computing an offline signature.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws GenericCryptographyException In case of a cryptography error.
     */
    public ComputeOfflineAuthResponse computeOfflineAuth(ComputeOfflineAuthRequest request) throws RemoteExecutionException, ActivationFailedException, GenericCryptographyException {

        final ResultStatusObject resultStatus = resultStatusUtil.getTestStatus(request.getActivationId());

        versionCheckService.checkVersion(resultStatus);

        final ComputeOfflineAuthenticationStepModel model = new ComputeOfflineAuthenticationStepModel();
        model.setQrCodeData(request.getQrCodeData());
        model.setPassword(request.getPassword());
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatus(resultStatus);

        final ObjectStepLogger stepLogger;
        try {
            stepLogger = new ObjectStepLogger();
            computeOfflineSignatureStep.execute(stepLogger, model.toMap());
            stepLogger.getItems()
                    .forEach(item -> StepItemLogger.log(logger, item));
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed", ex);
        }

        final Optional<String> otpCode = stepLogger.getItems().stream()
                .filter(item -> "authentication-offline-compute-finished".equals(item.id()))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> item.get("offlineAuthentication").toString())
                .findAny();

        if (otpCode.isPresent()) {
            resultStatusUtil.incrementCounter(request.getActivationId(), PowerAuthVersion.fromValue(config.getVersion()));
        }

        final ComputeOfflineAuthResponse response = new ComputeOfflineAuthResponse();
        response.setOtp(otpCode.orElse(null));
        return response;
    }

}
