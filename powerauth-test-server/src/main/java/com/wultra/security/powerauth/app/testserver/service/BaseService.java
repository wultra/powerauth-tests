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
import com.wultra.security.powerauth.app.testserver.database.TestConfigRepository;
import com.wultra.security.powerauth.app.testserver.database.entity.TestConfigEntity;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.Optional;

/**
 * Base service with shared business logic.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class BaseService {

    private final static Logger logger = LoggerFactory.getLogger(BaseService.class);

    protected final TestConfigRepository appConfigRepository;

    private static final KeyConvertor keyConvertor = new KeyConvertor();

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
     * Get master public key from test application configuration.
     * @param appConfig Test application configuration.
     * @return Master public key.
     * @throws GenericCryptographyException Thrown in case public key conversion fails.
     */
    protected PublicKey getMasterPublicKey(TestConfigEntity appConfig) throws GenericCryptographyException {
        final byte[] masterKeyBytes = BaseEncoding.base64().decode(appConfig.getMasterPublicKey());

        try {
            return keyConvertor.convertBytesToPublicKey(masterKeyBytes);
        } catch (Exception ex) {
            logger.warn("Key conversion failed, reason: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new GenericCryptographyException("Key conversion failed");
        }
    }

}
