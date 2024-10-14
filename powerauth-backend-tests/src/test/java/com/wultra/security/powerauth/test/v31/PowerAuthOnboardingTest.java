/*
 * PowerAuth test and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v31;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthOnboardingShared;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.EnabledIf;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

/**
 * PowerAuth onboarding tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
@EnabledIf(expression = "${powerauth.test.includeCustomTests}", loadContext = true)
class PowerAuthOnboardingTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_1;

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PowerAuthOnboardingShared.TestContext ctx;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeEach
    void setUp() throws IOException {
        EncryptStepModel encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        encryptModel.setVersion(VERSION);
        encryptModel.setScope("application");

        // Create temp status file
        File tempStatusFile = File.createTempFile("pa_status_" + VERSION, ".json");
        final JSONObject resultStatusObject = new JSONObject();

        // Model shared among tests
        CreateActivationStepModel activationModel = new CreateActivationStepModel();
        activationModel.setActivationName("test v" + VERSION + " onboarding");
        activationModel.setApplicationKey(config.getApplicationKey());
        activationModel.setApplicationSecret(config.getApplicationSecret());
        activationModel.setMasterPublicKey(config.getMasterPublicKey());
        activationModel.setHeaders(new HashMap<>());
        activationModel.setPassword(config.getPassword());
        activationModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        activationModel.setResultStatusObject(resultStatusObject);
        activationModel.setUriString(config.getEnrollmentServiceUrl());
        activationModel.setVersion(VERSION);
        activationModel.setDeviceInfo("backend-tests");

        GetStatusStepModel statusModel = new GetStatusStepModel();
        statusModel.setHeaders(new HashMap<>());
        statusModel.setResultStatusObject(resultStatusObject);
        statusModel.setUriString(config.getEnrollmentServiceUrl());
        statusModel.setVersion(VERSION);

        ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        ctx = new PowerAuthOnboardingShared.TestContext(powerAuthClient, config, activationModel, statusModel, encryptModel, objectMapper, stepLogger);
    }

    @Test
    void testSuccessfulOnboarding() throws Exception {
        PowerAuthOnboardingShared.testSuccessfulOnboarding(ctx);
    }

    @Test
    void testInvalidOtp() throws Exception {
        PowerAuthOnboardingShared.testInvalidOtp(ctx);
    }

    @Test
    void testOtpForNonExistingUser() throws Exception {
        PowerAuthOnboardingShared.testOtpForNonExistingUser(ctx);
    }

    @Test
    void testInvalidProcessId() {
        PowerAuthOnboardingShared.testInvalidProcessId(ctx);
    }

    @Test
    void testOnboardingCleanup() throws Exception {
        PowerAuthOnboardingShared.testOnboardingCleanup(ctx);
    }

    @Test
    void testResendPeriod() throws Exception {
        PowerAuthOnboardingShared.testResendPeriod(ctx);
    }

    @Test
    void testMaxProcesses() throws Exception {
        PowerAuthOnboardingShared.testMaxProcesses(ctx);
    }

    @Test
    void testOtpMaxFailedAttemptsReached() throws Exception {
        PowerAuthOnboardingShared.testOtpMaxFailedAttemptsReached(ctx);
    }

    @Test
    void testMaxAttemptsNotReached() throws Exception {
        PowerAuthOnboardingShared.testMaxAttemptsNotReached(ctx);
    }

    @Test
    void testResumeProcesses() throws Exception {
        PowerAuthOnboardingShared.testResumeProcesses(ctx);
    }

}
