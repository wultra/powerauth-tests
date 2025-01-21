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
package com.wultra.security.powerauth.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import com.wultra.security.powerauth.test.PowerAuthTestSetUp;
import com.wultra.security.powerauth.test.PowerAuthTestTearDown;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.util.RestClientConfiguration;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.security.PublicKey;
import java.security.Security;
import java.time.Duration;
import java.util.*;

/**
 * Configuration for the PowerAuth test.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
public class PowerAuthTestConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthTestConfiguration.class);

    @Value("${powerauth.rest.url:http://localhost:8080/powerauth-java-server/rest}")
    private String powerAuthRestUrl;

    @Value("${powerauth.integration.service.url:http://localhost:8080/enrollment-server}")
    private String powerAuthIntegrationUrl;

    @Value("${powerauth.enrollment.service.url:http://localhost:8080/enrollment-server}")
    private String enrollmentServiceUrl;

    @Value("${powerauth.enrollment-onboarding.service.url:http://localhost:8080/enrollment-server-onboarding}")
    private String enrollmentOnboardingServiceUrl;

    @Value("${powerauth.service.security.clientToken:}")
    private String clientToken;

    @Value("${powerauth.service.security.clientSecret:}")
    private String clientSecret;

    @Value("${powerauth.test.application.name:PA_Tests}")
    private String applicationName;

    @Value("${powerauth.test.application.version:default}")
    private String applicationVersion;

    @Value("${powerauth.test.identity.additionalDocSubmitValidationsEnabled:true}")
    private boolean additionalDocSubmitValidationsEnabled;

    @Value("${powerauth.test.identity.presence-check.skip:true}")
    private boolean skipPresenceCheck;

    @Value("${powerauth.test.identity.otp-verification.skip:true}")
    private boolean skipOtpVerification;

    @Value("${powerauth.test.identity.verificationOnSubmitEnabled:true}")
    private boolean verificationOnSubmitEnabled;

    @Value("${powerauth.test.assertMaxRetries:20}")
    private int assertMaxRetries;

    @Value("${powerauth.test.assertRetryWaitPeriod:PT1S}")
    private Duration assertRetryWaitPeriod;

    @Value("${powerauth.test.identity.result-verification.skip:false}")
    private boolean skipResultVerification;

    @Value("${powerauth.test.db.concurrency.skip:true}")
    private boolean skipDbConcurrencyTests;

    private String applicationVersionForTests;
    private String applicationKey;
    private String applicationSecret;

    private String applicationId;
    private String versionId;
    private PublicKey masterPublicKeyConverted;

    private Long loginOperationTemplateId;
    private String loginOperationTemplateName;

    private PowerAuthTestSetUp setUp;
    private PowerAuthTestTearDown tearDown;

    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final ObjectMapper objectMapper = RestClientConfiguration.defaultMapper();

    private final Map<PowerAuthVersion, File> statusFiles = new HashMap<>();
    private final Map<PowerAuthVersion, JSONObject> resultStatusObjects = new HashMap<>();
    private final Map<PowerAuthVersion, String> activationIds = new HashMap<>();
    private final Map<PowerAuthVersion, String> users = new HashMap<>();

    private final String password = "1234";

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
        config.setPowerAuthClientToken(clientToken);
        config.setPowerAuthClientSecret(clientSecret);
        config.setAcceptInvalidSslCertificate(true);
        try {
            return new PowerAuthRestClient(powerAuthRestUrl, config);
        } catch (PowerAuthClientException ex) {
            // Log the error in case Rest client initialization failed
            logger.error(ex.getMessage(), ex);
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

        // Prepare common userId
        final String userId = UUID.randomUUID().toString();

        // Create status files and users
        Arrays.stream(PowerAuthVersion.values()).forEach(version -> {
            try {
                final File statusFile = File.createTempFile("pa_status_" + version, ".json");
                statusFiles.put(version, statusFile);
                final String user = "TestUser_" + version + "_" + userId;
                users.put(version, user);
                resultStatusObjects.put(version, new JSONObject());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

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

    public String getPowerAuthIntegrationUrl() {
        return powerAuthIntegrationUrl;
    }

    public String getEnrollmentServiceUrl() {
        return enrollmentServiceUrl;
    }

    public String getEnrollmentOnboardingServiceUrl() {
        return enrollmentOnboardingServiceUrl;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getApplicationVersion() {
        return applicationVersionForTests;
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

    public File getStatusFile(PowerAuthVersion version) {
        return statusFiles.get(version);
    }

    public JSONObject getResultStatusObject(PowerAuthVersion version) {
        return resultStatusObjects.get(version);
    }

    public void setActivationId(String activationId, PowerAuthVersion version) {
        activationIds.put(version, activationId);
    }

    public String getActivationId(PowerAuthVersion version) {
        return activationIds.get(version);
    }

    public String getPassword() {
        return password;
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public String getUser(PowerAuthVersion version) {
        return users.get(version);
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

    public Duration getAssertRetryWaitPeriod() {
        return assertRetryWaitPeriod;
    }

    public int getAssertMaxRetries() {
        return assertMaxRetries;
    }

    public boolean isAdditionalDocSubmitValidationsEnabled() {
        return additionalDocSubmitValidationsEnabled;
    }

    public boolean isSkipPresenceCheck() {
        return skipPresenceCheck;
    }

    public boolean isSkipOtpVerification() {
        return skipOtpVerification;
    }

    public boolean isVerificationOnSubmitEnabled() {
        return verificationOnSubmitEnabled;
    }

    public boolean isSkipResultVerification() {
        return skipResultVerification;
    }

    public Long getLoginOperationTemplateId() {
        return loginOperationTemplateId;
    }

    public void setLoginOperationTemplateId(Long loginOperationTemplateId) {
        this.loginOperationTemplateId = loginOperationTemplateId;
    }

    public String getLoginOperationTemplateName() {
        return loginOperationTemplateName;
    }

    public void setLoginOperationTemplateName(String loginOperationTemplateName) {
        this.loginOperationTemplateName = loginOperationTemplateName;
    }
}