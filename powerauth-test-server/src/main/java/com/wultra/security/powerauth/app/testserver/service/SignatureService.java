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
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.model.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.app.testserver.model.enumeration.SignatureType;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeOfflineSignatureRequest;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeOnlineSignatureRequest;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeOfflineSignatureResponse;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeOnlineSignatureResponse;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.ComputeOfflineSignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.ComputeOfflineSignatureStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Map;

/**
 * Service for calculating PowerAuth signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class SignatureService extends BaseService {

    private final TestServerConfiguration config;
    private final ResultStatusService resultStatusUtil;
    private final VerifySignatureStep verifySignatureStep;
    private final ComputeOfflineSignatureStep computeOfflineSignatureStep;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param resultStatusUtil Result status utilities.
     * @param verifySignatureStep Verify signature step.
     * @param computeOfflineSignatureStep Compute offline signature step.
     */
    @Autowired
    public SignatureService(TestServerConfiguration config, TestConfigRepository appConfigRepository, ResultStatusService resultStatusUtil, VerifySignatureStep verifySignatureStep, ComputeOfflineSignatureStep computeOfflineSignatureStep) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.verifySignatureStep = verifySignatureStep;
        this.computeOfflineSignatureStep = computeOfflineSignatureStep;
    }

    /**
     * Compute an online signature.
     * @param request Request for computing an online signature.
     * @return Response for computing an online signature.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws AppConfigNotFoundException In case application configuration is not found.
     */
    @SuppressWarnings("unchecked")
    public ComputeOnlineSignatureResponse computeOnlineSignature(ComputeOnlineSignatureRequest request) throws RemoteExecutionException, ActivationFailedException, AppConfigNotFoundException {

        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final JSONObject resultStatusObject = resultStatusUtil.getTestStatus(request.getActivationId());

        final VerifySignatureStepModel model = new VerifySignatureStepModel();
        model.setHttpMethod(request.getHttpMethod());
        model.setResourceId(request.getResourceId());
        model.setSignatureType(SignatureTypeConverter.convert(request.getSignatureType()));
        if (request.getRequestBody() != null) {
            model.setData(Base64.getDecoder().decode(request.getRequestBody()));
        }
        model.setPassword(request.getPassword());
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatusObject(resultStatusObject);
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setDryRun(true);

        String authHeader = null;
        try {
            final ObjectStepLogger stepLogger = new ObjectStepLogger();
            verifySignatureStep.execute(stepLogger, model.toMap());
            for (StepItem item: stepLogger.getItems()) {
                StepItemLogger.log(logger, item);
                if ("signature-verify-request-sent".equals(item.id())) {
                    final Map<String, Object> requestMap = (Map<String, Object>) item.object();
                    final Map<String, Object> requestHeadersMap = (Map<String, Object>) requestMap.get("requestHeaders");
                    authHeader = requestHeadersMap.get("X-PowerAuth-Authorization").toString();
                    resultStatusUtil.incrementCounter(request.getActivationId());
                }
            }
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed");
        }

        final ComputeOnlineSignatureResponse response = new ComputeOnlineSignatureResponse();
        response.setAuthHeader(authHeader);
        return response;
    }

    /**
     * Compute an offline signature.
     * @param request Request for computing an offline signature.
     * @return Response for computing an offline signature.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     */
    @SuppressWarnings("unchecked")
    public ComputeOfflineSignatureResponse computeOfflineSignature(ComputeOfflineSignatureRequest request) throws RemoteExecutionException, ActivationFailedException {

        final JSONObject resultStatusObject = resultStatusUtil.getTestStatus(request.getActivationId());

        final ComputeOfflineSignatureStepModel model = new ComputeOfflineSignatureStepModel();
        model.setQrCodeData(request.getQrCodeData());
        model.setPassword(request.getPassword());
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatusObject(resultStatusObject);

        String otpCode = null;
        try {
            final ObjectStepLogger stepLogger = new ObjectStepLogger();
            computeOfflineSignatureStep.execute(stepLogger, model.toMap());
            for (StepItem item: stepLogger.getItems()) {
                StepItemLogger.log(logger, item);
                if ("signature-offline-compute-finished".equals(item.id())) {
                    final Map<String, Object> resultMap = (Map<String, Object>) item.object();
                    otpCode = resultMap.get("offlineSignature").toString();
                    resultStatusUtil.incrementCounter(request.getActivationId());
                }
            }
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed");
        }

        final ComputeOfflineSignatureResponse response = new ComputeOfflineSignatureResponse();
        response.setOtp(otpCode);
        return response;
    }

}
