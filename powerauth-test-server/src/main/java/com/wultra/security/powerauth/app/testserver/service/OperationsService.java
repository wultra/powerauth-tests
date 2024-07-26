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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.app.testserver.config.TestServerConfiguration;
import com.wultra.security.powerauth.app.testserver.database.TestConfigRepository;
import com.wultra.security.powerauth.app.testserver.database.entity.TestConfigEntity;
import com.wultra.security.powerauth.app.testserver.errorhandling.ActivationFailedException;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.errorhandling.SignatureVerificationException;
import com.wultra.security.powerauth.app.testserver.model.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.app.testserver.model.request.GetOperationsRequest;
import com.wultra.security.powerauth.app.testserver.model.request.OperationApproveInternalRequest;
import com.wultra.security.powerauth.app.testserver.model.request.OperationRejectInternalRequest;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import com.wultra.security.powerauth.lib.mtoken.model.response.OperationListResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.VerifyTokenStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifyTokenStepModel;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

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
    private final VerifySignatureStep verifySignatureStep;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param resultStatusUtil Result status utilities.
     * @param verifyTokenStep Step for verifying a token.
     * @param verifySignatureStep Step for verifying signature.
     */
    @Autowired
    public OperationsService(TestServerConfiguration config, ResultStatusService resultStatusUtil, TestConfigRepository appConfigRepository, VerifyTokenStep verifyTokenStep, VerifySignatureStep verifySignatureStep) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.verifyTokenStep = verifyTokenStep;
        this.verifySignatureStep = verifySignatureStep;
    }


    /**
     * Get pending operations.
     * @param request Request to get pending operations.
     * @return Response with pending operations.
     * @throws RemoteExecutionException In case internal calls fail.
     * @throws RestClientException In case REST client call fails (fetching operations).
     * @throws SignatureVerificationException In case signature verification fails.
     * @throws ActivationFailedException In case activation is not found.
     */
    @SuppressWarnings("unchecked")
    public OperationListResponse getOperations(GetOperationsRequest request) throws RemoteExecutionException, RestClientException, SignatureVerificationException, ActivationFailedException {
        final JSONObject resultStatusObject = resultStatusUtil.getTestStatus(request.getActivationId());

        final VerifyTokenStepModel model = new VerifyTokenStepModel();
        model.setTokenId(request.getTokenId());
        model.setTokenSecret(request.getTokenSecret());
        model.setDryRun(true);
        model.setHttpMethod("POST");
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatusObject(resultStatusObject);

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

        resultStatusUtil.persistResultStatus(resultStatusObject);

        final String header = stepLogger.getItems().stream()
                .filter(item -> "Sending Request".equals(item.name()))
                .map(item -> (Map<String, Object>) item.object())
                .map(item -> (Map<String, String>) item.get("requestHeaders"))
                .map(item -> item.get("X-PowerAuth-Token"))
                .findAny()
                .orElseThrow(() -> new SignatureVerificationException("Unable to generate token"));

        final HttpHeaders headers = new HttpHeaders();
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
     */
    public Response approveOperation(OperationApproveInternalRequest request) throws RemoteExecutionException, AppConfigNotFoundException, SignatureVerificationException, ActivationFailedException {
        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final JSONObject resultStatusObject = resultStatusUtil.getTestStatus(request.getActivationId());

        final Map<String, String> map = new HashMap<>();
        map.put("id", request.getOperationId());
        map.put("data", request.getOperationData());

        final byte[] payload;
        try {
            String payloadString = new ObjectMapper().writeValueAsString(new ObjectRequest<>(map));
            payload = payloadString.getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new SignatureVerificationException("Unable to serialize data", e);
        }

        final VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.setData(payload);
        model.setResourceId("/operation/authorize");
        model.setUriString(config.getEnrollmentServiceUrl() + "/api/auth/token/app/operation/authorize");
        model.setHttpMethod("POST");
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setSignatureType(SignatureTypeConverter.convert(request.getSignatureType()));
        model.setPassword(request.getPassword());
        model.setVersion(config.getVersion());
        model.setResultStatusObject(resultStatusObject);

        verifySignature(model, resultStatusObject);

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
     */
    public Response rejectOperation(OperationRejectInternalRequest request) throws AppConfigNotFoundException, ActivationFailedException, SignatureVerificationException, RemoteExecutionException {
        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final JSONObject resultStatusObject = resultStatusUtil.getTestStatus(request.getActivationId());

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
        } catch (JsonProcessingException e) {
            throw new SignatureVerificationException("Unable to serialize data", e);
        }

        final VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.setData(payload);
        model.setResourceId("/operation/cancel");
        model.setUriString(config.getEnrollmentServiceUrl() + "/api/auth/token/app/operation/cancel");
        model.setHttpMethod("POST");
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION);
        model.setVersion(config.getVersion());
        model.setResultStatusObject(resultStatusObject);

        verifySignature(model, resultStatusObject);

        return new Response();
    }

    @SuppressWarnings("java:S2201")
    private void verifySignature(final VerifySignatureStepModel model, final JSONObject resultStatusObject) throws RemoteExecutionException, SignatureVerificationException {
        final ObjectStepLogger stepLogger;
        try {
            stepLogger = new ObjectStepLogger();
            verifySignatureStep.execute(stepLogger, model.toMap());
            stepLogger.getItems()
                    .forEach(item -> StepItemLogger.log(logger, item));
        } catch (Exception ex) {
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed", ex);
        }

        resultStatusUtil.persistResultStatus(resultStatusObject);

        stepLogger.getItems().stream()
                .map(StepItem::name)
                .filter("Signature verified"::equals)
                .findAny()
                .orElseThrow(() -> new SignatureVerificationException("Signature verification failed"));
    }
}
