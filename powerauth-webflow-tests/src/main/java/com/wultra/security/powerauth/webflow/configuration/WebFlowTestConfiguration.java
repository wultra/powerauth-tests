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
package com.wultra.security.powerauth.webflow.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import com.wultra.security.powerauth.webflow.test.PowerAuthTestSetUp;
import com.wultra.security.powerauth.webflow.test.PowerAuthTestTearDown;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.lib.nextstep.client.NextStepClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.File;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.UUID;

/**
 * Configuration for the Web Flow tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
public class WebFlowTestConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(WebFlowTestConfiguration.class);

    @Value("${powerauth.rest.url}")
    private String powerAuthRestUrl;

    @Value("${powerauth.webflow.service.url}")
    private String powerAuthWebFlowUrl;

    @Value("${powerauth.nextstep.service.url}")
    private String nextStepServiceUrl;

    @Value("${powerauth.test.application.name}")
    private String applicationName;

    @Value("${powerauth.test.application.version}")
    private String applicationVersion;

    @Value("${powerauth.webflow.client.url}")
    private String webFlowClientUrl;

    @Value("${powerauth.service.security.clientToken}")
    private String clientToken;

    @Value("${powerauth.service.security.clientSecret}")
    private String clientSecret;

    private String applicationVersionForTests;
    private String applicationKey;
    private String applicationSecret;

    private String applicationId;
    private String versionId;
    private PublicKey masterPublicKeyConverted;

    private PowerAuthTestSetUp setUp;
    private PowerAuthTestTearDown tearDown;

    private KeyConvertor keyConvertor = new KeyConvertor();
    private ObjectMapper objectMapper = RestClientConfiguration.defaultMapper();

    // Temporary storage
    private File statusFile;
    private JSONObject resultStatusObject = new JSONObject();
    private String activationId;
    private String user;

    private String password = "1234";

    private WebDriver webDriver;
    private WebDriverWait webDriverWait;

    @Autowired
    public void setPowerAuthTestSetUp(PowerAuthTestSetUp setUp) {
        this.setUp = setUp;
    }

    @Autowired
    public void setPowerAuthTestTearDown(PowerAuthTestTearDown tearDown) {
        this.tearDown = tearDown;
    }

    /**
     * Initialize PowerAuth client.
     * @return PowerAuth client.
     */
    @Bean
    public PowerAuthClient powerAuthClient() {
        PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
        config.setAcceptInvalidSslCertificate(true);
        config.setPowerAuthClientToken(clientToken);
        config.setPowerAuthClientSecret(clientSecret);
        try {
            return new PowerAuthRestClient(powerAuthRestUrl, config);
        } catch (PowerAuthClientException ex) {
            // Log the error in case Rest client initialization failed
            logger.error(ex.getMessage(), ex);
            return null;
        }
    }

    @Bean
    public NextStepClient nextStepClient() {
        try {
            return new NextStepClient(nextStepServiceUrl);
        } catch (Exception ex) {
            return null;
        }
    }

    @Bean
    public PowerAuthTestSetUp testSetUp() {
        return new PowerAuthTestSetUp();
    }

    @Bean
    public PowerAuthTestTearDown testTearDown() {
        return new PowerAuthTestTearDown();
    }

    @PostConstruct
    public void setUp() throws Exception {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());

        // Create status file and user
        statusFile = File.createTempFile("webflow_status", ".json");
        user = "TestUser_" + UUID.randomUUID().toString();

        // Random application name
        applicationVersionForTests = applicationVersion + "_" + System.currentTimeMillis();

        setUp.execute();
    }

    @PreDestroy
    public void tearDown() throws PowerAuthClientException {
        tearDown.execute();
    }

    public String getPowerAuthRestUrl() {
        return powerAuthRestUrl;
    }

    public String getPowerAuthWebFlowUrl() {
        return powerAuthWebFlowUrl;
    }

    public String getNextStepServiceUrl() {
        return nextStepServiceUrl;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getApplicationVersion() {
        return applicationVersionForTests;
    }

    public String getWebFlowClientUrl() {
        return webFlowClientUrl;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public String getApplicationVersionId() {
        return versionId;
    }

    public void setApplicationVersionId(String versionId) {
        this.versionId = versionId;
    }

    public String getApplicationKey() {
        return applicationKey;
    }

    public String getApplicationSecret() {
        return applicationSecret;
    }

    public PublicKey getMasterPublicKey() {
        return masterPublicKeyConverted;
    }

    public KeyConvertor getKeyConvertor() {
        return keyConvertor;
    }

    public File getStatusFile() {
        return statusFile;
    }

    public JSONObject getResultStatusObject() {
        return resultStatusObject;
    }

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public String getPassword() {
        return password;
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public String getUser() {
        return user;
    }

    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }

    public void setMasterPublicKey(String masterPublicKey) {
        // Convert master public key
        byte[] masterKeyBytes = Base64.getDecoder().decode(masterPublicKey);
        try {
            masterPublicKeyConverted = keyConvertor.convertBytesToPublicKey(masterKeyBytes);
        } catch (Exception ex) {
            logger.error(ex.getMessage(), ex);
        }
    }

    public WebDriver setUpWebDriver() {
        setUp.setUpWebDriver();
        return webDriver;
    }

    public WebDriver getWebDriver() {
        return webDriver;
    }

    public void setWebDriver(WebDriver webDriver) {
        this.webDriver = webDriver;
    }

    public WebDriverWait getWebDriverWait() {
        return webDriverWait;
    }

    public void setWebDriverWait(WebDriverWait webDriverWait) {
        this.webDriverWait = webDriverWait;
    }
}