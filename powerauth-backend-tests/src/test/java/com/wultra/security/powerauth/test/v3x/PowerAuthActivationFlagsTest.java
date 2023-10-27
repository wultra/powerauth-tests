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
package com.wultra.security.powerauth.test.v3x;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthActivationFlagsShared;
import io.getlime.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Activation flag tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = {"com.wultra.security.powerauth", "io.getlime.security.powerauth"})
public class PowerAuthActivationFlagsTest {

    // Test only in the latestPowerAuth protocol version
    private static final String VERSION = "3.2";

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private PrepareActivationStepModel model;
    private File tempStatusFile;

    @LocalServerPort
    private int port;

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
        model.setActivationName("test v31 flags");
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
    void activationFlagCrudTest() throws Exception {
        PowerAuthActivationFlagsShared.activationFlagCrudTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationFlagLookupTest() throws Exception {
        PowerAuthActivationFlagsShared.activationFlagLookupTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationProviderFlagTest() throws Exception {
        PowerAuthActivationFlagsShared.activationProviderFlagTest(powerAuthClient, config, tempStatusFile, port, VERSION);
    }
}
