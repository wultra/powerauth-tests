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
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeOnlineSignatureRequest;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeOnlineSignatureResponse;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Service for calculating PowerAuth signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class SignatureService extends BaseService {

    private final static Logger logger = LoggerFactory.getLogger(SignatureService.class);

    private final TestServerConfiguration config;
    private final ResultStatusService resultStatusUtil;
    private final VerifySignatureStep verifySignatureStep;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param resultStatusUtil Result status utilities.
     * @param verifySignatureStep Verify signature step.
     */
    @Autowired
    public SignatureService(TestServerConfiguration config, TestConfigRepository appConfigRepository, ResultStatusService resultStatusUtil, VerifySignatureStep verifySignatureStep) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.verifySignatureStep = verifySignatureStep;
    }

    /**
     * Compute a token digest.
     * @param request Request for computing a token digest.
     * @return Response for computing a token digest.
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
        model.setSignatureType(PowerAuthSignatureTypes.getEnumFromString(request.getSignatureType()));
        if (request.getRequestBody() != null) {
            model.setData(BaseEncoding.base64().decode(request.getRequestBody()));
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
                if ("signature-verify-request-sent".equals(item.getId())) {
                    final Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                    final Map<String, Object> requestHeadersMap = (Map<String, Object>) responseMap.get("requestHeaders");
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
}
