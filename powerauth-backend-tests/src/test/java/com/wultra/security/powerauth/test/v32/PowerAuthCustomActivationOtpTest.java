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
package com.wultra.security.powerauth.test.v32;

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthCustomActivationOtpShared;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.GetStatusStepModel;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth custom activation OTP tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = "com.wultra.security.powerauth")
class PowerAuthCustomActivationOtpTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_2;

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private CreateActivationStepModel createModel;
    private GetStatusStepModel statusModel;

    private static File dataFile;
    private File tempStatusFile;
    private ObjectStepLogger stepLogger;

    private final String validOtpValue = "1234-5678";
    private final String invalidOtpValue = "8765-4321";

    @LocalServerPort
    private int port;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeAll
    static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() throws IOException {
        // Create temp status files
        tempStatusFile = File.createTempFile("pa_status_" + VERSION, ".json");

        // Models shared among tests
        createModel = new CreateActivationStepModel();
        createModel.setActivationName("test v" + VERSION);
        createModel.setApplicationKey(config.getApplicationKey());
        createModel.setApplicationSecret(config.getApplicationSecret());
        createModel.setMasterPublicKey(config.getMasterPublicKey());
        createModel.setHeaders(new HashMap<>());
        createModel.setPassword(config.getPassword());
        createModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        createModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        createModel.setUriString("http://localhost:" + port);
        createModel.setVersion(VERSION);
        createModel.setDeviceInfo("backend-tests");

        statusModel = new GetStatusStepModel();
        statusModel.setHeaders(new HashMap<>());
        statusModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        statusModel.setUriString(config.getPowerAuthIntegrationUrl());
        statusModel.setVersion(VERSION);

        // Prepare step logger
        stepLogger = new ObjectStepLogger(System.out);
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void customActivationOtpValidTest() throws Exception {
        PowerAuthCustomActivationOtpShared.customActivationOtpValidTest(powerAuthClient, createModel, statusModel, stepLogger, validOtpValue, invalidOtpValue);
    }

    @Test
    void customActivationOtpInvalidTest() throws Exception {
        PowerAuthCustomActivationOtpShared.customActivationOtpInvalidTest(powerAuthClient, createModel, stepLogger, validOtpValue, invalidOtpValue);
    }

}
