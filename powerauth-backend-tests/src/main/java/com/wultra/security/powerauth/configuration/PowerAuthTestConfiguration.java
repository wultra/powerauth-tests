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
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.test.PowerAuthTestSetUp;
import com.wultra.security.powerauth.test.PowerAuthTestTearDown;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.lib.cmd.util.RestClientConfiguration;
import io.getlime.security.powerauth.lib.nextstep.client.NextStepClient;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.apache.wss4j.dom.WSConstants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.soap.security.wss4j2.Wss4jSecurityInterceptor;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.File;
import java.security.PublicKey;
import java.security.Security;
import java.util.UUID;

/**
 * Configuration for the PowerAuth test.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
public class PowerAuthTestConfiguration {

    @Value("${powerauth.service.url}")
    private String powerAuthServiceUrl;

    @Value("${powerauth.integration.service.url}")
    private String powerAuthIntegrationUrl;

    @Value("${powerauth.nextstep.service.url}")
    private String nextStepServiceUrl;

    @Value("${powerauth.service.security.clientToken}")
    private String clientToken;

    @Value("${powerauth.service.security.clientSecret}")
    private String clientSecret;

    @Value("${powerauth.test.application.name}")
    private String applicationName;

    @Value("${powerauth.test.application.version}")
    private String applicationVersion;

    @Value("${powerauth.test.masterPublicKey}")
    private String masterPublicKey;

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

    // Version 3.0 temporary storage
    private File statusFileV3;
    private JSONObject resultStatusObjectV3 = new JSONObject();
    private String activationIdV3;
    private String userV2;

    // Version 2.1 temporary storage
    private File statusFileV2;
    private JSONObject resultStatusObjectV2 = new JSONObject();
    private String activationIdV2;
    private String userV3;

    private String password = "1234";

    @Autowired
    public void setPowerAuthTestSetUp(PowerAuthTestSetUp setUp) {
        this.setUp = setUp;
    }

    @Autowired
    public void setPowerAuthTestTearDown(PowerAuthTestTearDown tearDown) {
        this.tearDown = tearDown;
    }

    /**
     * Initialize security interceptor.
     * @return Security interceptor.
     */
    @Bean
    public Wss4jSecurityInterceptor securityInterceptor() {
        Wss4jSecurityInterceptor wss4jSecurityInterceptor = new Wss4jSecurityInterceptor();
        wss4jSecurityInterceptor.setSecurementActions("UsernameToken");
        wss4jSecurityInterceptor.setSecurementUsername(clientToken);
        wss4jSecurityInterceptor.setSecurementPassword(clientSecret);
        wss4jSecurityInterceptor.setSecurementPasswordType(WSConstants.PW_TEXT);
        return wss4jSecurityInterceptor;
    }

    /**
     * Initialize JAXB marshaller.
     * @return JAXB marshaller.
     */
    @Bean
    public Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setContextPaths("io.getlime.powerauth.soap.v2", "io.getlime.powerauth.soap.v3");
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
        if (!clientToken.isEmpty()) {
            ClientInterceptor interceptor = securityInterceptor();
            client.setInterceptors(new ClientInterceptor[]{interceptor});
        }
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

        // Convert master public key
        byte[] masterKeyBytes = BaseEncoding.base64().decode(masterPublicKey);
        masterPublicKeyConverted = PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(masterKeyBytes);

        // Create status file for version 3.0
        statusFileV3 = File.createTempFile("pa_status_v3", ".json");

        // Create status file for version 2.1
        statusFileV2 = File.createTempFile("pa_status_v2", ".json");

        // Create random user for version 3.0
        userV3 = UUID.randomUUID().toString();

        // Create random user for version 2.1
        userV2 = UUID.randomUUID().toString();

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

    public String getPowerAuthIntegrationUrl() {
        return powerAuthIntegrationUrl;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getApplicationVersion() {
        return applicationVersionForTests;
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

    public File getStatusFileV3() {
        return statusFileV3;
    }

    public JSONObject getResultStatusObjectV3() {
        return resultStatusObjectV3;
    }

    public File getStatusFileV2() {
        return statusFileV2;
    }

    public JSONObject getResultStatusObjectV2() {
        return resultStatusObjectV2;
    }

    public String getActivationIdV3() {
        return activationIdV3;
    }

    public void setActivationIdV3(String activationIdV3) {
        this.activationIdV3 = activationIdV3;
    }

    public String getActivationIdV2() {
        return activationIdV2;
    }

    public void setActivationIdV2(String activationIdV2) {
        this.activationIdV2 = activationIdV2;
    }

    public String getPassword() {
        return password;
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public String getUserV2() {
        return userV2;
    }

    public String getUserV3() {
        return userV3;
    }

    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    public void setApplicationSecret(String applicationSecret) {
        this.applicationSecret = applicationSecret;
    }
}