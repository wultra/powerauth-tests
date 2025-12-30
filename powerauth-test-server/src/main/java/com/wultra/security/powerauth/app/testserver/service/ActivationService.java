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
import com.wultra.security.powerauth.app.testserver.errorhandling.*;
import com.wultra.security.powerauth.app.testserver.model.request.CreateActivationRequest;
import com.wultra.security.powerauth.app.testserver.model.response.CreateActivationResponse;
import com.wultra.security.powerauth.app.testserver.util.StepItemLogger;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.ConfirmActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.ConfirmActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import com.wultra.security.powerauth.lib.cmd.util.SecurityUtil;
import com.wultra.security.powerauth.lib.cmd.util.config.SdkConfiguration;
import com.wultra.security.powerauth.lib.cmd.util.config.SdkConfigurationSerializer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

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
    private final ConfirmActivationStep confirmActivationStep;

    /**
     * Service constructor.
     * @param config Test server configuration.
     * @param appConfigRepository Test application configuration repository.
     * @param resultStatusUtil Result status utilities.
     * @param prepareActivationStep Prepare activation step.
     */
    @Autowired
    public ActivationService(TestServerConfiguration config, TestConfigRepository appConfigRepository, ResultStatusService resultStatusUtil, PrepareActivationStep prepareActivationStep, ConfirmActivationStep confirmActivationStep) {
        super(appConfigRepository);
        this.config = config;
        this.resultStatusUtil = resultStatusUtil;
        this.prepareActivationStep = prepareActivationStep;
        this.confirmActivationStep = confirmActivationStep;
    }

    /**
     * Create an activation using activation code.
     * @param request Create activation request.
     * @return Create activation response.
     * @throws AppConfigNotFoundException Thrown when application configuration is not found.
     * @throws GenericCryptographyException Thrown when cryptography computation fails.
     */
    @Transactional
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws AppConfigNotFoundException, GenericCryptographyException, RemoteExecutionException, ActivationFailedException, AppConfigInvalidException {
        // TODO - input validation
        final String applicationId = request.getApplicationId();
        final TestConfigEntity appConfig = getTestAppConfig(applicationId);
        final PowerAuthVersion version = PowerAuthVersion.fromValue(config.getVersion());
        final SharedSecretAlgorithm algorithm = resolveSharedSecretAlgorithm(request, version);

        if (config.getVersion().startsWith("3") && algorithm != SharedSecretAlgorithm.EC_P256) {
            throw new AppConfigInvalidException("PowerAuth protocol version 3 does not support algorithm " + algorithm);
        }

        final SdkConfiguration sdkConfiguration = loadSdkConfiguration(appConfig);
        final ValidationResult configValidationResult = validateSdkConfig(sdkConfiguration, algorithm);
        if (!configValidationResult.isValid()) {
            throw new AppConfigInvalidException("Invalid mobile SDK config: " +  configValidationResult.error());
        }

        final PublicKey publicKeyP256 = getMasterPublicKeyP256(sdkConfiguration);
        final PublicKey publicKeyP384 = getMasterPublicKeyP384(sdkConfiguration);
        final PublicKey publicKeyMlDsa65 = getMasterPublicKeyMlDsa65(sdkConfiguration);
        final PublicKey publicKeyMlDsa87 = getMasterPublicKeyMlDsa87(sdkConfiguration);

        final ResultStatusObject resultStatusObject = new ResultStatusObject();

        // Prepare activation
        final PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationCode(request.getActivationCode());
        model.setActivationName(request.getActivationName());
        model.setApplicationKey(sdkConfiguration.appKey());
        model.setApplicationSecret(sdkConfiguration.appSecret());
        model.setMasterPublicKeyP256(publicKeyP256);
        model.setMasterPublicKeyP384(publicKeyP384);
        model.setMasterPublicKeyMlDsa65(publicKeyMlDsa65);
        model.setMasterPublicKeyMlDsa87(publicKeyMlDsa87);
        model.setSharedSecretAlgorithm(algorithm);
        model.setHeaders(new HashMap<>());
        model.setPassword(request.getPassword());
        model.setResultStatus(resultStatusObject);
        model.setUriString(config.getEnrollmentServiceUrl());
        model.setVersion(config.getVersion());
        model.setDeviceInfo("backend-tests");
        model.setAdditionalActivationOtp(request.getActivationOtp());

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

        boolean confirmed = false;

        if (config.getVersion().startsWith("4") && request.isConfirmActivation()) {
            final ConfirmActivationStepModel confirmModel = new ConfirmActivationStepModel();
            confirmModel.setApplicationKey(appConfig.getApplicationKey());
            confirmModel.setApplicationSecret(appConfig.getApplicationSecret());
            confirmModel.setHeaders(new HashMap<>());
            confirmModel.setPassword(request.getPassword());
            confirmModel.setResultStatus(resultStatusObject);
            confirmModel.setUriString(config.getEnrollmentServiceUrl());
            confirmModel.setVersion(config.getVersion());
            confirmModel.setEnableBiometry(request.isEnableBiometry());

            final ObjectStepLogger stepLoggerConfirm;
            try {
                stepLoggerConfirm = new ObjectStepLogger();
                confirmActivationStep.execute(stepLoggerConfirm, confirmModel.toMap());
                stepLoggerConfirm.getItems().forEach(item -> StepItemLogger.log(logger, item));

                resultStatusUtil.incrementCounter(activationId, PowerAuthVersion.fromValue(config.getVersion()));

                confirmed = true;
            } catch (Exception ex) {
                logger.warn("Remote execution failed, reason: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
                throw new RemoteExecutionException("Remote execution failed", ex);
            }
        }

        // TODO - extract response from steps
        final CreateActivationResponse response = new CreateActivationResponse();
        response.setActivationId(activationId);
        response.setConfirmed(confirmed);
        return response;
    }

    private static SharedSecretAlgorithm resolveSharedSecretAlgorithm(final CreateActivationRequest request, final PowerAuthVersion version) throws GenericCryptographyException {
        try {
            if (StringUtils.hasText(request.getAlgorithm())) {
                return SharedSecretAlgorithm.valueOf(request.getAlgorithm());
            }
            return SecurityUtil.getDefaultSharedSecretAlgorithm(version);
        } catch (IllegalArgumentException e) {
            throw new GenericCryptographyException("Unsupported algorithm " + request.getAlgorithm(), e);
        }
    }

    private static SdkConfiguration loadSdkConfiguration(final TestConfigEntity appConfig) throws AppConfigInvalidException {
        if (appConfig.getMobileSdkConfig() == null) {
            throw new AppConfigInvalidException("Mobile SDK configuration is missing");
        }
        return SdkConfigurationSerializer.deserialize(appConfig.getMobileSdkConfig());
    }

    private static ValidationResult validateSdkConfig(final SdkConfiguration sdkConfig, final SharedSecretAlgorithm algorithm) {
        if (!StringUtils.hasText(sdkConfig.appKey())) {
            ValidationResult.error("Application key is missing");
        }

        if (!StringUtils.hasText(sdkConfig.appSecret())) {
            ValidationResult.error("Application secret is missing");
        }

        final boolean p256 = StringUtils.hasText(sdkConfig.masterPublicKeyP256());
        final boolean p384 = StringUtils.hasText(sdkConfig.masterPublicKeyP384());
        final boolean mldsa65 = StringUtils.hasText(sdkConfig.masterPublicKeyMlDsa65());
        final boolean mldsa87 = StringUtils.hasText(sdkConfig.masterPublicKeyMlDsa87());

        return switch (algorithm) {
            case EC_P256 -> p256
                    ? ValidationResult.ok()
                    : ValidationResult.error("Algorithm EC_P256 requires P-256 master public key");

            case EC_P384 -> p384
                    ? ValidationResult.ok()
                    : ValidationResult.error("Algorithm EC_P384 requires P-384 master public key");

            case EC_P384_ML_L3 -> {
                if (!p384) yield ValidationResult.error("Algorithm EC_P384_ML_L3 requires P-384 master public key");
                if (!mldsa65) yield ValidationResult.error("Algorithm EC_P384_ML_L3 requires ML-DSA-65 master public key");
                yield ValidationResult.ok();
            }

            case EC_P384_ML_L5 -> {
                if (!p384) yield ValidationResult.error("Algorithm EC_P384_ML_L5 requires P-384 master public key");
                if (!mldsa87) yield ValidationResult.error("Algorithm EC_P384_ML_L5 requires ML-DSA-87 master public key");
                yield ValidationResult.ok();
            }

            default -> ValidationResult.error("Unsupported algorithm " + algorithm);
        };
    }

    record ValidationResult(boolean isValid, String error) {
        public static ValidationResult ok() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult error(final String error) {
            return new ValidationResult(false, error);
        }
    }

}
