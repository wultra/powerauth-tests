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
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigInvalidException;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.model.request.ConfigureApplicationRequest;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.lib.cmd.util.config.SdkConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.config.SdkConfigurationSerializer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application service.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ApplicationService extends BaseService {

    /**
     * Service constructor.
     * @param appConfigRepository Test application configuration repository.
     */
    @Autowired
    public ApplicationService(TestConfigRepository appConfigRepository) {
        super(appConfigRepository);
    }

    /**
     * Configure an application.
     * @param request Configure an application request.
     * @return Configure an application response.
     * @throws AppConfigInvalidException Thrown in case mobile SDK configuration is invalid.
     */
    @Transactional
    public Response configureApplication(final ConfigureApplicationRequest request) throws AppConfigInvalidException {
        final String applicationId = request.getApplicationId();
        final String applicationName = request.getApplicationName();
        final String mobileSdkConfig = request.getMobileSdkConfig();

        final TestConfigEntity appConfig = getOrCreateTestAppConfig(applicationId);

        final String applicationKey;
        final String applicationSecret;
        final String masterPublicKey;

        if (mobileSdkConfig != null) {
            final SdkConfiguration config;
            try {
                config = SdkConfigurationSerializer.deserialize(mobileSdkConfig);
            } catch (Exception ex) {
                throw new AppConfigInvalidException("Invalid mobile SDK configuration");
            }
            if (config == null) {
                throw new AppConfigInvalidException("Missing mobile SDK configuration");
            }
            applicationKey = config.appKeyBase64();
            applicationSecret = config.appSecretBase64();
            masterPublicKey = config.masterPublicKeyBase64();
        } else {
            applicationKey = request.getApplicationKey();
            applicationSecret = request.getApplicationSecret();
            masterPublicKey = request.getMasterPublicKey();
        }

        appConfig.setApplicationName(applicationName);
        appConfig.setApplicationKey(applicationKey);
        appConfig.setApplicationSecret(applicationSecret);
        appConfig.setMasterPublicKey(masterPublicKey);

        appConfigRepository.save(appConfig);

        return new Response();
    }

    private TestConfigEntity getOrCreateTestAppConfig(final String applicationId) {
        TestConfigEntity appConfig;
        try {
            appConfig = getTestAppConfig(applicationId);
            logger.info("Test application will be updated: {}", applicationId);
        } catch (AppConfigNotFoundException ex ) {
            appConfig = new TestConfigEntity();
            appConfig.setApplicationId(applicationId);
            logger.info("Test application will be created: {}", applicationId);
        }
        return appConfig;
    }

}
