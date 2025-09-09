/*
 * PowerAuth test and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v40;

import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.ChangePasswordStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.test.shared.v4.PowerAuthAuthenticationShared;
import com.wultra.security.powerauth.test.shared.v4.PowerAuthDynamicFactorShared;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth dynamic factor tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthDynamicFactorTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V4_0;

    private PowerAuthTestConfiguration config;
    private static File dataFile;
    private ChangePasswordStepModel changePasswordModel;
    private VerifyAuthenticationStepModel verifyAuthenticationModel;
    private ObjectStepLogger stepLogger;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @BeforeAll
    static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".txt");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("Confidential test message used for testing");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() throws IOException {
        changePasswordModel = new ChangePasswordStepModel();
        changePasswordModel.setApplicationKey(config.getApplicationKey());
        changePasswordModel.setApplicationSecret(config.getApplicationSecret());
        changePasswordModel.setHeaders(new HashMap<>());
        changePasswordModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        changePasswordModel.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        changePasswordModel.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        changePasswordModel.setUriString(config.getPowerAuthIntegrationUrl());
        changePasswordModel.setVersion(VERSION);

        verifyAuthenticationModel = new VerifyAuthenticationStepModel();
        verifyAuthenticationModel.setApplicationKey(config.getApplicationKey());
        verifyAuthenticationModel.setApplicationSecret(config.getApplicationSecret());
        verifyAuthenticationModel.setData(Files.readAllBytes(Paths.get(dataFile.getAbsolutePath())));
        verifyAuthenticationModel.setHeaders(new HashMap<>());
        verifyAuthenticationModel.setHttpMethod("POST");
        verifyAuthenticationModel.setResourceId("/pa/auth/validate");
        verifyAuthenticationModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        verifyAuthenticationModel.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        verifyAuthenticationModel.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        verifyAuthenticationModel.setUriString(config.getPowerAuthIntegrationUrl() + "/pa/v4/auth/validate");
        verifyAuthenticationModel.setVersion(VERSION);
    }

    @Test
    void passwordChangeTest() throws Exception {
        stepLogger = new ObjectStepLogger(System.out);
        changePasswordModel.setPassword(config.getPassword());
        changePasswordModel.setPasswordNew("3820");
        PowerAuthDynamicFactorShared.passwordChangeTest(changePasswordModel, stepLogger);

        stepLogger = new ObjectStepLogger(System.out);
        verifyAuthenticationModel.setPassword("3820");
        PowerAuthAuthenticationShared.authValidTest(verifyAuthenticationModel, stepLogger);

        stepLogger = new ObjectStepLogger(System.out);
        changePasswordModel.setPassword("3820");
        changePasswordModel.setPasswordNew(config.getPassword());
        PowerAuthDynamicFactorShared.passwordChangeTest(changePasswordModel, stepLogger);

        stepLogger = new ObjectStepLogger(System.out);
        verifyAuthenticationModel.setPassword(config.getPassword());
        PowerAuthAuthenticationShared.authValidTest(verifyAuthenticationModel, stepLogger);
    }

}
