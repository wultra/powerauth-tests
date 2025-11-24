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

import com.wultra.security.powerauth.app.testserver.database.TestConfigRepository;
import com.wultra.security.powerauth.app.testserver.database.entity.TestConfigEntity;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.lib.cmd.util.config.SdkConfiguration;
import com.wultra.security.powerauth.lib.cmd.util.config.SdkConfigurationSerializer;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;

/**
 * Base service with shared business logic.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Slf4j
public class BaseService {

    protected final TestConfigRepository appConfigRepository;

    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();

    public BaseService(TestConfigRepository appConfigRepository) {
        this.appConfigRepository = appConfigRepository;
    }

    /**
     * Get test application configuration.
     * @param applicationId Application identifier.
     * @return Test application configuration.
     * @throws AppConfigNotFoundException Thrown when application configuration is not found.
     */
    protected TestConfigEntity getTestAppConfig(String applicationId) throws AppConfigNotFoundException {
        final Optional<TestConfigEntity> appConfigOptional = appConfigRepository.findById(applicationId);

        if (appConfigOptional.isEmpty()) {
            throw new AppConfigNotFoundException("Application configuration was not found for application ID: " + applicationId);
        }

        return appConfigOptional.get();
    }

    /**
     * Get P-256 master public key from test application configuration.
     * @param appConfig Test application configuration.
     * @return Master public key.
     * @throws GenericCryptographyException Thrown in case public key conversion fails.
     */
    protected PublicKey getMasterPublicKeyP256(TestConfigEntity appConfig) throws GenericCryptographyException {
        if (appConfig.getMobileSdkConfig() == null) {
            throw new GenericCryptographyException("Mobile SDK configuration is missing");
        }
        final SdkConfiguration sdkConfig = SdkConfigurationSerializer.deserialize(appConfig.getMobileSdkConfig());
        final String masterPublicKeyP256 = sdkConfig.masterPublicKeyP256();
        final byte[] masterKeyBytes = Base64.getDecoder().decode(masterPublicKeyP256);
        try {
            return KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P256, masterKeyBytes);
        } catch (Exception ex) {
            logger.warn("Key conversion failed for P-256 master public key, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new GenericCryptographyException("Key conversion failed");
        }
    }

    /**
     * Get P-384 master public key from test application configuration.
     * @param appConfig Test application configuration.
     * @return Master public key.
     * @throws GenericCryptographyException Thrown in case public key conversion fails.
     */
    protected PublicKey getMasterPublicKeyP384(TestConfigEntity appConfig) throws GenericCryptographyException {
        if (appConfig.getMobileSdkConfig() == null) {
            throw new GenericCryptographyException("Mobile SDK configuration is missing");
        }
        final SdkConfiguration sdkConfig = SdkConfigurationSerializer.deserialize(appConfig.getMobileSdkConfig());
        final String masterPublicKeyP384 = sdkConfig.masterPublicKeyP384();
        final byte[] masterKeyBytes = Base64.getDecoder().decode(masterPublicKeyP384);
        try {
            return KEY_CONVERTOR_EC.convertBytesToPublicKey(EcCurve.P384, masterKeyBytes);
        } catch (Exception ex) {
            logger.warn("Key conversion failed for P-384 master public key, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new GenericCryptographyException("Key conversion failed");
        }
    }

    /**
     * Get ML-DSA-67 master public key from test application configuration.
     * @param appConfig Test application configuration.
     * @return Master public key.
     * @throws GenericCryptographyException Thrown in case public key conversion fails.
     */
    protected PublicKey getMasterPublicKeyMlDsa65(TestConfigEntity appConfig) throws GenericCryptographyException {
        if (appConfig.getMobileSdkConfig() == null) {
            throw new GenericCryptographyException("Mobile SDK configuration is missing");
        }
        final SdkConfiguration sdkConfig = SdkConfigurationSerializer.deserialize(appConfig.getMobileSdkConfig());
        final String masterPublicKeyMlDsa65 = sdkConfig.masterPublicKeyMlDsa65();
        final byte[] masterKeyBytes = Base64.getDecoder().decode(masterPublicKeyMlDsa65);
        try {
            return KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(masterKeyBytes);
        } catch (Exception ex) {
            logger.warn("Key conversion failed for ML-DSA-67 master public key, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new GenericCryptographyException("Key conversion failed");
        }
    }

}
