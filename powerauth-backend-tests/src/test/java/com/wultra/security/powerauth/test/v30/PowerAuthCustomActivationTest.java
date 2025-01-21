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
package com.wultra.security.powerauth.test.v30;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthCustomActivationShared;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
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
 * PowerAuth custom activation tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = "com.wultra.security.powerauth")
class PowerAuthCustomActivationTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_0;

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private CreateActivationStepModel model;
    private static File dataFile;
    private File tempStatusFile;
    private ObjectStepLogger stepLogger;

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
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_" + VERSION, ".json");

        // Model shared among tests
        model = new CreateActivationStepModel();
        model.setActivationName("test " + VERSION);
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObject(VERSION));
        model.setUriString("http://localhost:" + port);
        model.setVersion(VERSION);
        model.setDeviceInfo("backend-tests");

        // Prepare step logger
        stepLogger = new ObjectStepLogger(System.out);
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void customActivationValidTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationValidTest(powerAuthClient, model, stepLogger);
    }

    @Test
    void customActivationValid2Test() throws Exception {
        PowerAuthCustomActivationShared.customActivationValid2Test(powerAuthClient, model, stepLogger);
    }

    @Test
    void customActivationValid3Test() throws Exception {
        PowerAuthCustomActivationShared.customActivationValid3Test(powerAuthClient, model, stepLogger);
    }

    @Test
    void customActivationMissingUsernameTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationMissingUsernameTest(config, model, stepLogger);
    }

    @Test
    void customActivationEmptyUsernameTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationEmptyUsernameTest(config, model, stepLogger);
    }

    @Test
    void customActivationUsernameTooLongTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationUsernameTooLongTest(config, model, stepLogger);
    }

    @Test
    void customActivationBadMasterPublicKeyTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationBadMasterPublicKeyTest(config, model, stepLogger);
    }

    @Test
    void customActivationUnsupportedApplicationTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationUnsupportedApplicationTest(powerAuthClient, config, model, stepLogger);
    }

    @Test
    void customActivationInvalidApplicationKeyTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationInvalidApplicationKeyTest(config, model, stepLogger);
    }

    @Test
    void customActivationInvalidApplicationSecretTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationInvalidApplicationSecretTest(config, model, stepLogger);
    }

    @Test
    void customActivationDoubleCommitTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationDoubleCommitTest(powerAuthClient, model, stepLogger);
    }

    @Test
    void customActivationSignatureMaxFailedTest() throws Exception {
        PowerAuthCustomActivationShared.customActivationSignatureMaxFailedTest(powerAuthClient, config, model, stepLogger, dataFile, tempStatusFile, port, VERSION);
    }

}
