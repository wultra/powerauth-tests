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
import com.wultra.security.powerauth.app.testserver.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.app.testserver.model.response.CreateTokenResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.logging.model.StepItem;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateTokenStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.CreateTokenStep;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.security.PublicKey;
import java.util.Map;

/**
 * Service for creating new tokens.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class CreateTokenService extends BaseService {

    private final static Logger logger = LoggerFactory.getLogger(CreateTokenService.class);

    private final TestServerConfiguration config;
    private final ResultStatusService resultStatusUtil;
    private final CreateTokenStep createTokenStep;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param resultStatusUtil Result status utilities.
     * @param createTokenStep Prepare token.
     */
    @Autowired
    public CreateTokenService(TestServerConfiguration config, TestConfigRepository appConfigRepository, ResultStatusService resultStatusUtil, CreateTokenStep createTokenStep) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.createTokenStep = createTokenStep;
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

        final CreateTokenStepModel model = new CreateTokenStepModel();
        model.setApplicationKey(appConfig.getApplicationKey());
        model.setApplicationSecret(appConfig.getApplicationSecret());
        model.setPassword(request.getPassword());
        model.setMasterPublicKey(publicKey);
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        model.setVersion(config.getVersion());
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setResultStatusObject(resultStatusObject);

        String tokenId = null;
        String tokenSecret = null;
        try {
            final ObjectStepLogger stepLogger = new ObjectStepLogger();
            createTokenStep.execute(stepLogger, model.toMap());
            for (StepItem item: stepLogger.getItems()) {
                if ("Token successfully obtained".equals(item.getName())) {
                    final Map<String, Object> responseMap = (Map<String, Object>) item.getObject();
                    tokenId = (String) responseMap.get("tokenId");
                    tokenSecret = (String) responseMap.get("tokenSecret");
                    break;
                }
            }
        } catch (Exception ex) {
            logger.warn("Remote execution failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new RemoteExecutionException("Remote execution failed");
        }

        resultStatusUtil.persistResultStatus(resultStatusObject);

        final CreateTokenResponse result = new CreateTokenResponse();
        result.setTokenId(tokenId);
        result.setTokenSecret(tokenSecret);
        return result;
    }

}
