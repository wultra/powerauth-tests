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
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.webflow.test.PowerAuthTestSetUp;
import com.wultra.security.powerauth.webflow.test.PowerAuthTestTearDown;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.lib.nextstep.client.NextStepClient;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.File;
import java.security.PublicKey;
import java.security.Security;
import java.util.UUID;

/**
 * Configuration for the Web Flow tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
public class WebFlowTestConfiguration {

    @Value("${powerauth.service.url}")
    private String powerAuthServiceUrl;

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

    private String applicationVersionForTests;
    private String applicationKey;
    private String applicationSecret;

    private Long applicationId;
    private Long versionId;
    private PublicKey masterPublicKeyConverted;

    private PowerAuthTestSetUp setUp;
    private PowerAuthTestTearDown tearDown;

    private CryptoProviderUtil keyConversion;
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
     * Initialize JAXB marshaller.
     * @return JAXB marshaller.
     */
    @Bean
    public Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPaths("io.getlime.powerauth.soap.v3");
        return marshaller;
    }

    /**
     * Initialize PowerAuth client.
     * @param marshaller JAXB marshaller.
     * @return PowerAuth client.
     */
    @Bean
    public PowerAuthServiceClient powerAuthClient(Jaxb2Marshaller marshaller) {
        PowerAuthServiceClient client = new PowerAuthServiceClient();
        client.setDefaultUri(powerAuthServiceUrl);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        return client;
    }

    @Bean
    public NextStepClient nextStepClient() {
        return new NextStepClient(nextStepServiceUrl);
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
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());

        keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

        // Configure REST client
        RestClientConfiguration.configure();

        // Create status file and user
        statusFile = File.createTempFile("webflow_status", ".json");
        user = "TestUser_" + UUID.randomUUID().toString();

        // Random application name
        applicationVersionForTests = applicationVersion + "_" + System.currentTimeMillis();

        setUp.execute();
    }

    @PreDestroy
    public void tearDown() {
        tearDown.execute();
    }

    public String getPowerAuthServiceUrl() {
        return powerAuthServiceUrl;
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

    public Long getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(Long applicationId) {
        this.applicationId = applicationId;
    }

    public Long getApplicationVersionId() {
        return versionId;
    }

    public void setApplicationVersionId(Long versionId) {
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

    public CryptoProviderUtil getKeyConversion() {
        return keyConversion;
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
        byte[] masterKeyBytes = BaseEncoding.base64().decode(masterPublicKey);
        try {
            masterPublicKeyConverted = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(masterKeyBytes);
        } catch (Exception ex) {
        }
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