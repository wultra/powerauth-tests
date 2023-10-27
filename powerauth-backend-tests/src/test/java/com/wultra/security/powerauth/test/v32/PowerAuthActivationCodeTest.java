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

import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthActivationCodeShared;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AfterEach;
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

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
public class PowerAuthActivationCodeTest {

    private static final String VERSION = "3.2";

    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel activationModel;
    private VerifySignatureStepModel signatureModel;
    private File tempStatusFile;
    private ObjectStepLogger stepLogger;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @BeforeEach
    void setUp() throws IOException {
        // Create temp status file
        tempStatusFile = File.createTempFile("pa_status_v" + VERSION.replace(".", ""), ".json");

        // Model shared among tests
        activationModel = new PrepareActivationStepModel();
        activationModel.setActivationName("test v" + VERSION);
        activationModel.setApplicationKey(config.getApplicationKey());
        activationModel.setApplicationSecret(config.getApplicationSecret());
        activationModel.setMasterPublicKey(config.getMasterPublicKey());
        activationModel.setHeaders(new HashMap<>());
        activationModel.setPassword(config.getPassword());
        activationModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        activationModel.setResultStatusObject(new JSONObject());
        activationModel.setUriString(config.getPowerAuthIntegrationUrl());
        activationModel.setVersion(VERSION);
        activationModel.setDeviceInfo("backend-tests");

        signatureModel = new VerifySignatureStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setSignatureType(PowerAuthSignatureTypes.POSSESSION_BIOMETRY);
        signatureModel.setPassword(config.getPassword());
        signatureModel.setHttpMethod("POST");
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setStatusFileName(tempStatusFile.getAbsolutePath());
        signatureModel.setResultStatusObject(config.getResultStatusObjectV32());
        signatureModel.setVersion(VERSION);
        signatureModel.setDryRun(false);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    @EnabledIf(expression = "${powerauth.test.includeCustomTests}", loadContext = true)
    void activationUsingActivationCodeTest() throws Exception {
        PowerAuthActivationCodeShared.activationUsingActivationCodeTest(config, activationModel, signatureModel, stepLogger);
    }
}
