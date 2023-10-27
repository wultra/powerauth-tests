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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthActivationShared;
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import org.json.simple.JSONObject;
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

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthActivationTest {

    private static final String VERSION = "3.2";

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private File tempStatusFile;

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
        tempStatusFile = File.createTempFile("pa_status_v" + VERSION.replace(".", ""), ".json");

        // Model shared among tests
        model = new PrepareActivationStepModel();
        model.setActivationName("test v" + VERSION);
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(new JSONObject());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setVersion(VERSION);
        model.setDeviceInfo("backend-tests");
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void activationPrepareTest() throws Exception {
        PowerAuthActivationShared.activationPrepareTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationNonExistentTest() throws PowerAuthClientException {
        PowerAuthActivationShared.activationNonExistentTest(powerAuthClient);
    }

    @Test
    void activationPrepareUnsupportedApplicationTest() throws Exception {
        PowerAuthActivationShared.activationPrepareUnsupportedApplicationTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationPrepareExpirationTest() throws Exception {
        PowerAuthActivationShared.activationPrepareExpirationTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationPrepareWithoutInitTest() throws Exception {
        PowerAuthActivationShared.activationPrepareWithoutInitTest(config, model);
    }

    @Test
    void activationPrepareBadMasterPublicKeyTest() throws Exception {
        PowerAuthActivationShared.activationPrepareBadMasterPublicKeyTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationStatusTest() throws Exception {
        PowerAuthActivationShared.activationStatusTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationInvalidApplicationKeyTest() throws Exception {
        PowerAuthActivationShared.activationInvalidApplicationKeyTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationInvalidApplicationSecretTest() throws Exception {
        PowerAuthActivationShared.activationInvalidApplicationSecretTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void lookupActivationsTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsNonExistentUserTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsNonExistentUserTest(powerAuthClient);
    }

    @Test
    void lookupActivationsApplicationTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsApplicationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsNonExistentApplicationTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsNonExistentApplicationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsStatusTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsStatusTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsInvalidStatusTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsInvalidStatusTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsDateValidTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsDateValidTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsDateInvalidTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsDateInvalidTest(powerAuthClient, config, VERSION);
    }

    @Test
    void updateActivationStatusTest() throws Exception {
        PowerAuthActivationShared.updateActivationStatusTest(powerAuthClient, config, model, VERSION);
    }

}
