/*
 * PowerAuth test and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v32;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthActivationCommitPhaseShared;
import com.wultra.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
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
 * Tests for commit phase.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthActivationCommitPhaseTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_2;

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private GetStatusStepModel statusModel;
    private File tempStatusFile;

    private final String validOtpValue = "1234-5678";
    private final String invalidOtpValue = "8765-4321";

    private static final PowerAuthClientActivation activation = new PowerAuthClientActivation();

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
        model.setActivationName("test v" + VERSION);
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
        PowerAuthActivationCommitPhaseShared.validOtpOnKeysExchangeTest(powerAuthClient, config, model, validOtpValue, VERSION);
    }

    @Test
    void invalidOtpOnKeysExchangeTest() throws Exception {
        PowerAuthActivationCommitPhaseShared.invalidOtpOnKeysExchangeTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void validOtpOnCommitTest() throws Exception {
        PowerAuthActivationCommitPhaseShared.validOtpOnCommitTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void invalidOtpOnCommitTest() throws Exception {
        PowerAuthActivationCommitPhaseShared.invalidOtpOnCommitTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void updateValidOtpOnCommitTest() throws Exception {
        PowerAuthActivationCommitPhaseShared.updateValidOtpOnCommitTest(powerAuthClient, config, model, statusModel, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void updateInvalidOtpOnCommitTest() throws Exception {
        PowerAuthActivationCommitPhaseShared.updateInvalidOtpOnCommitTest(powerAuthClient, config, model, validOtpValue, invalidOtpValue, VERSION);
    }

    @Test
    void wrongActivationInitParamTest() {
        PowerAuthActivationCommitPhaseShared.wrongActivationInitParamTest(powerAuthClient, config, VERSION);
    }

}
