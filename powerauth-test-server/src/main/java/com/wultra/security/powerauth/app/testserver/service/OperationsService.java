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

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.app.testserver.config.TestServerConfiguration;
import com.wultra.security.powerauth.app.testserver.database.TestConfigRepository;
import com.wultra.security.powerauth.app.testserver.database.entity.TestConfigEntity;
import com.wultra.security.powerauth.app.testserver.errorhandling.*;
import com.wultra.security.powerauth.app.testserver.model.converter.AuthenticationCodeTypeConverter;
import com.wultra.security.powerauth.app.testserver.model.request.GetOperationsRequest;
import com.wultra.security.powerauth.app.testserver.model.request.OperationApproveInternalRequest;
import com.wultra.security.powerauth.app.testserver.model.request.OperationRejectInternalRequest;
import com.wultra.security.powerauth.app.testserver.util.PowerAuthVersionService;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.VerifyAuthenticationStep;
import com.wultra.security.powerauth.lib.cmd.steps.VerifyTokenStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.mtoken.model.response.OperationListResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for working with operations.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class OperationsService extends BaseService {

    private final TestServerConfiguration config;
    private final ResultStatusService resultStatusUtil;
    private final VerifyTokenStep verifyTokenStep;
    private final VerifyAuthenticationStep verifyAuthenticationStep;
    private final PowerAuthVersionService powerAuthVersionService;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param resultStatusUtil Result status utilities.
     * @param appConfigRepository Test application configuration repository.
     * @param verifyTokenStep Step for verifying a token.
     * @param verifyAuthenticationStep Step for verifying signature.
     * @param powerAuthVersionService PowerAuth version mapping service.
     */
    @Autowired
    public OperationsService(TestServerConfiguration config, ResultStatusService resultStatusUtil, TestConfigRepository appConfigRepository, VerifyTokenStep verifyTokenStep, VerifyAuthenticationStep verifyAuthenticationStep, PowerAuthVersionService powerAuthVersionService) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.verifyTokenStep = verifyTokenStep;
        this.verifyAuthenticationStep = verifyAuthenticationStep;
        this.powerAuthVersionService = powerAuthVersionService;
    }


    /**
     * Get pending operations.
     * @param request Request to get pending operations.
     * @return Response with pending operations.
     * @throws RemoteExecutionException In case internal calls fail.
     * @throws RestClientException In case REST client call fails (fetching operations).
     * @throws SignatureVerificationException In case signature verification fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws GenericCryptographyException In case of a cryptography error.
     */
    public OperationListResponse getOperations(GetOperationsRequest request) throws RemoteExecutionException, RestClientException, SignatureVerificationException, ActivationFailedException, GenericCryptographyException {
        final ResultStatusObject resultStatus = resultStatusUtil.getTestStatus(request.getActivationId());
        final PowerAuthVersion version = powerAuthVersionService.mapVersionToProtocol(resultStatus.getVersion());

        final VerifyTokenStepModel model = new VerifyTokenStepModel();
        model.setTokenId(request.getTokenId());
        model.setTokenSecret(request.getTokenSecret());
        model.setDryRun(true);
        model.setHttpMethod("POST");
        model.setVersion(version);
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatus(resultStatus);

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

        resultStatusUtil.persistResultStatus(resultStatus);

        final String header = stepLogger.getItems().stream()
                .filter(item -> "Sending Request".equals(item.name()))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (Map<String, String>) item.get("requestHeaders"))
                .map(item -> item.get("X-PowerAuth-Token"))
                .findAny()
                .orElseThrow(() -> new SignatureVerificationException("Unable to generate token"));

        final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.put("X-PowerAuth-Token", Collections.singletonList(header));
        headers.add(HttpHeaders.ACCEPT_LANGUAGE, LocaleContextHolder.getLocale().getLanguage());

        final RestClient restClient = new DefaultRestClient(config.getEnrollmentServiceUrl());
        final ResponseEntity<ObjectResponse<OperationListResponse>> responseEntity = restClient.post("/api/auth/token/app/operation/list", null, null, headers, new ParameterizedTypeReference<>() {});
        final ObjectResponse<OperationListResponse> entityBody = responseEntity.getBody();
        if (entityBody == null) {
            throw new SignatureVerificationException("Unable to fetch pending operations");
        }
        return entityBody.getResponseObject();
    }

    /**
     * Service to approve an operation.
     * @param request Operation approval request.
     * @return Operation approval response.
     * @throws RemoteExecutionException In case internal calls fail.
     * @throws SignatureVerificationException In case signature verification fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws AppConfigNotFoundException In case app configuration is not found.
     * @throws GenericCryptographyException In case of a cryptography error.
     */
    public Response approveOperation(OperationApproveInternalRequest request) throws RemoteExecutionException, AppConfigNotFoundException, SignatureVerificationException, ActivationFailedException, GenericCryptographyException {
        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final ResultStatusObject resultStatus = resultStatusUtil.getTestStatus(request.getActivationId());
        final PowerAuthVersion version = powerAuthVersionService.mapVersionToProtocol(resultStatus.getVersion());

        final Map<String, Object> map = new HashMap<>();
        map.put("id", request.getOperationId());
        map.put("data", request.getOperationData());
        map.put("mobileTokenData", request.getMobileTokenData());

        final byte[] payload;
        try {
            String payloadString = new ObjectMapper().writeValueAsString(new ObjectRequest<>(map));
            payload = payloadString.getBytes(StandardCharsets.UTF_8);
        } catch (JacksonException e) {
            throw new SignatureVerificationException("Unable to serialize data", e);
        }

        final VerifyAuthenticationStepModel model = new VerifyAuthenticationStepModel();
        model.setData(payload);
        model.setResourceId("/operation/authorize");
        model.setUriString(config.getEnrollmentServiceUrl() + "/api/auth/token/app/operation/authorize");
        model.setHttpMethod("POST");
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setAuthenticationCodeType(AuthenticationCodeTypeConverter.convert(request.getAuthenticationCodeType() != null
                ? request.getAuthenticationCodeType()
                : request.getSignatureType()));
        model.setPassword(request.getPassword());
        model.setVersion(version);
        model.setResultStatus(resultStatus);

        verifySignature(model, resultStatus);

        return new Response();
    }

    /**
     * Service to reject an operation.
     * @param request Operation approval request.
     * @return Operation approval response.
     * @throws RemoteExecutionException In case internal calls fail.
     * @throws SignatureVerificationException In case signature verification fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws AppConfigNotFoundException In case app configuration is not found.
     * @throws GenericCryptographyException In case of a cryptography error.
     */
    public Response rejectOperation(OperationRejectInternalRequest request) throws AppConfigNotFoundException, ActivationFailedException, SignatureVerificationException, RemoteExecutionException, GenericCryptographyException {
        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final ResultStatusObject resultStatus = resultStatusUtil.getTestStatus(request.getActivationId());
        final PowerAuthVersion version = powerAuthVersionService.mapVersionToProtocol(resultStatus.getVersion());

        final String operationId = request.getOperationId();
        final String reason = request.getReason();

        final Map<String, String> map = new HashMap<>();
        map.put("id", operationId);
        if (reason != null) {
            map.put("reason", reason);
        }

        final byte[] payload;
        try {
            String payloadString = new ObjectMapper().writeValueAsString(new ObjectRequest<>(map));
            payload = payloadString.getBytes(StandardCharsets.UTF_8);
        } catch (JacksonException e) {
            throw new SignatureVerificationException("Unable to serialize data", e);
        }

        final VerifyAuthenticationStepModel model = new VerifyAuthenticationStepModel();
        model.setData(payload);
        model.setResourceId("/operation/cancel");
        model.setUriString(config.getEnrollmentServiceUrl() + "/api/auth/token/app/operation/cancel");
        model.setHttpMethod("POST");
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION);
        model.setVersion(version);
        model.setResultStatus(resultStatus);

        verifySignature(model, resultStatus);

        return new Response();
    }

    @SuppressWarnings("java:S2201")
    private void verifySignature(final VerifyAuthenticationStepModel model, final ResultStatusObject resultStatus) throws RemoteExecutionException, SignatureVerificationException {
        final ObjectStepLogger stepLogger;
        try {
            stepLogger = new ObjectStepLogger();
            verifyAuthenticationStep.execute(stepLogger, model.toMap());
            stepLogger.getItems()
                    .forEach(item -> StepItemLogger.log(logger, item));
        } catch (Exception ex) {
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed", ex);
        }

        resultStatusUtil.persistResultStatus(resultStatus);

        stepLogger.getItems().stream()
                .map(StepItem::name)
                .filter("Authentication code verified"::equals)
                .findAny()
                .orElseThrow(() -> new SignatureVerificationException("Authentication verification failed"));
    }
}
