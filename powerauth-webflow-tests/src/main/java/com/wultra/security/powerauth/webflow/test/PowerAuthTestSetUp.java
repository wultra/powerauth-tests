/*
 * PowerAuth test and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.webflow.test;

import com.wultra.security.powerauth.webflow.configuration.WebFlowTestConfiguration;
import io.getlime.powerauth.soap.v3.*;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.v3.PrepareActivationStep;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.openqa.selenium.Capabilities;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.safari.SafariOptions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Global test setup.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthTestSetUp {

    private PowerAuthServiceClient powerAuthClient;
    private WebFlowTestConfiguration config;

    @Autowired
    public void setPowerAuthServiceClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(WebFlowTestConfiguration config) {
        this.config = config;
    }

    public void execute() throws Exception {
        printTestConfiguration();
        createApplication();
        createActivation();
    }

    private void printTestConfiguration() {
        System.out.println("Test settings:");
        System.out.println("powerauth.service.url=" + config.getPowerAuthServiceUrl());
        System.out.println("powerauth.webflow.service.url=" + config.getPowerAuthWebFlowUrl());
        System.out.println("powerauth.nextstep.service.url=" + config.getNextStepServiceUrl());
        System.out.println("powerauth.webflow.client.url=" + config.getWebFlowClientUrl());
    }

    private void createApplication() {
        // Create application if it does not exist
        List<GetApplicationListResponse.Applications> applications = powerAuthClient.getApplicationList();
        boolean applicationExists = false;
        for (GetApplicationListResponse.Applications app: applications) {
            if (app.getApplicationName().equals(config.getApplicationName())) {
                applicationExists = true;
                config.setApplicationId(app.getId());
            }
        }
        if (!applicationExists) {
            CreateApplicationResponse response = powerAuthClient.createApplication(config.getApplicationName());
            assertNotEquals(0, response.getApplicationId());
            assertEquals(config.getApplicationName(), response.getApplicationName());
            config.setApplicationId(response.getApplicationId());
        }


        // Create application version if it does not exist
        GetApplicationDetailResponse detail = powerAuthClient.getApplicationDetail(config.getApplicationId());
        boolean versionExists = false;
        for (GetApplicationDetailResponse.Versions appVersion: detail.getVersions()) {
            if (appVersion.getApplicationVersionName().equals(config.getApplicationVersion())) {
                versionExists = true;
                config.setApplicationVersionId(appVersion.getApplicationVersionId());
                config.setApplicationKey(appVersion.getApplicationKey());
                config.setApplicationSecret(appVersion.getApplicationSecret());
            }
        }
        config.setMasterPublicKey(detail.getMasterPublicKey());
        if (!versionExists) {
            CreateApplicationVersionResponse versionResponse = powerAuthClient.createApplicationVersion(config.getApplicationId(), config.getApplicationVersion());
            assertNotEquals(0, versionResponse.getApplicationVersionId());
            assertEquals(config.getApplicationVersion(), versionResponse.getApplicationVersionName());
            config.setApplicationVersionId(versionResponse.getApplicationVersionId());
            config.setApplicationKey(versionResponse.getApplicationKey());
            config.setApplicationSecret(versionResponse.getApplicationSecret());
        } else {
            // Make sure application version is supported
            powerAuthClient.supportApplicationVersion(config.getApplicationVersionId());
        }
    }

    private void createActivation() throws Exception {
        // Init activation
        InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId(config.getUser());
        InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        // Prepare activation
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationCode(initResponse.getActivationCode());
        model.setActivationName("test webflow");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(config.getStatusFile().getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObject());
        model.setUriString(config.getPowerAuthWebFlowUrl());
        model.setVersion("3.1");

        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().isSuccess());

        // Commit activation
        CommitActivationResponse commitResponse = powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        assertEquals(initResponse.getActivationId(), commitResponse.getActivationId());
        System.out.println("committed: "+initResponse.getActivationId());

        config.setActivationId(initResponse.getActivationId());
    }

    public void setUpWebDriver() {
        try {
            Capabilities capabilities = new SafariOptions();
            WebDriver driver = new RemoteWebDriver(new URL("http://localhost:10000"), capabilities);
            driver.manage().timeouts().implicitlyWait(10, TimeUnit.SECONDS);
            driver.manage().window().maximize();
            config.setWebDriver(driver);
            WebDriverWait webDriverWait = new WebDriverWait(driver, 10);
            config.setWebDriverWait(webDriverWait);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
