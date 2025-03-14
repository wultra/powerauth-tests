/*
 * PowerAuth test and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthActivationOtpShared;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth activation OTP tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthActivationOtpTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_1;

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private GetStatusStepModel statusModel;
    private File tempStatusFile;

    private final String validOtpValue = "1234-5678";
    private final String invalidOtpValue = "8765-4321";

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @BeforeEach
    void setUp() throws IOException {
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_" + VERSION, ".json");

        // Models shared among tests
        model = new PrepareActivationStepModel();
        model.setActivationName("test v31");
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObject(VERSION));
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion(VERSION);
        model.setDeviceInfo("backend-tests");

        statusModel = new GetStatusStepModel();
        statusModel.setHeaders(new HashMap<>());
        statusModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setVersion(VERSION);
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void validOtpOnKeysExchangeTest() throws Exception {
        PowerAuthActivationOtpShared.validOtpOnKeysExchangeTest(powerAuthClient, config, model, validOtpValue, VERSION);
    }

    @Test
    void invalidOtpOnKeysExchangeTest() throws Exception {
        PowerAuthActivationOtpShared.invalidOtpOnKeysExchangeTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void validOtpOnCommitTest() throws Exception {
        PowerAuthActivationOtpShared.validOtpOnCommitTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void invalidOtpOnCommitTest() throws Exception {
        PowerAuthActivationOtpShared.invalidOtpOnCommitTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void updateValidOtpOnCommitTest() throws Exception {
        PowerAuthActivationOtpShared.updateValidOtpOnCommitTest(powerAuthClient, config, model, statusModel, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void updateInvalidOtpOnCommitTest() throws Exception {
        PowerAuthActivationOtpShared.updateInvalidOtpOnCommitTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void wrongActivationInitParamTest1() {
        PowerAuthActivationOtpShared.wrongActivationInitParamTest1(powerAuthClient, config, VERSION);
    }

    @Test
    void wrongActivationInitParamTest2() {
        PowerAuthActivationOtpShared.wrongActivationInitParamTest2(powerAuthClient, config, VERSION);
    }

    @Test
    void wrongActivationInitParamTest3() {
        PowerAuthActivationOtpShared.wrongActivationInitParamTest3(powerAuthClient, config, VERSION);
    }

    @Test
    void wrongActivationInitParamTest4() {
        PowerAuthActivationOtpShared.wrongActivationInitParamTest4(powerAuthClient, config, VERSION);
    }

    @Test
    void missingOtpOnCommitTest() throws Exception {
        PowerAuthActivationOtpShared.missingOtpOnCommitTest(powerAuthClient, config, model, validOtpValue, VERSION);
    }

    @Test
    void missingOtpOnKeysExchangeTest() throws Exception {
        PowerAuthActivationOtpShared.missingOtpOnKeysExchangeTest(powerAuthClient, config, model, validOtpValue, VERSION);
    }

}
