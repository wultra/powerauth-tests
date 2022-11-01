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
import com.wultra.security.powerauth.app.testserver.model.request.ConfigureApplicationRequest;
import io.getlime.core.rest.model.base.response.Response;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

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
     */
    @Transactional
    public Response configureApplication(ConfigureApplicationRequest request) {
        final String applicationId = request.getApplicationId();
        final String applicationName = request.getApplicationName();
        final String applicationKey = request.getApplicationKey();
        final String applicationSecret = request.getApplicationSecret();
        final String masterPublicKey = request.getMasterPublicKey();

        TestConfigEntity appConfig = getOrCreateTestAppConfig(applicationId);

        appConfig.setApplicationName(applicationName);
        appConfig.setApplicationKey(applicationKey);
        appConfig.setApplicationSecret(applicationSecret);
        appConfig.setMasterPublicKey(masterPublicKey);

        appConfigRepository.save(appConfig);

        return new Response();
    }

    private TestConfigEntity getOrCreateTestAppConfig(String applicationId) {
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
