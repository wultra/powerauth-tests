/*
 * PowerAuth test and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthRecoveryShared;
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

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthRecoveryTest {

    private static final String VERSION = "3.1";

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
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
        tempStatusFile = File.createTempFile("pa_status_recovery_v" + VERSION.replace(".", ""), ".json");
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    @Test
    void activationRecoveryTest() throws Exception {
        PowerAuthRecoveryShared.activationRecoveryTest(powerAuthClient, config, tempStatusFile, VERSION);
    }

    @Test
    void removeActivationAndRevokeRecoveryCodeTest() throws Exception {
        PowerAuthRecoveryShared.removeActivationAndRevokeRecoveryCodeTest(powerAuthClient, config, tempStatusFile, VERSION);
    }

    @Test
    void activationRecoveryInvalidPukTest() throws Exception {
        PowerAuthRecoveryShared.activationRecoveryInvalidPukTest(powerAuthClient, config, tempStatusFile, VERSION);
    }

    @Test
    void recoveryPostcardTest() throws Exception {
        PowerAuthRecoveryShared.recoveryPostcardTest(powerAuthClient, config, tempStatusFile, VERSION);
    }

    @Test
    void recoveryPostcardInvalidPukIndexTest() throws Exception {
        PowerAuthRecoveryShared.recoveryPostcardInvalidPukIndexTest(powerAuthClient, config, tempStatusFile, VERSION);
    }

    // TODO - revoke test

    // TODO - negative tests for postcards

}
