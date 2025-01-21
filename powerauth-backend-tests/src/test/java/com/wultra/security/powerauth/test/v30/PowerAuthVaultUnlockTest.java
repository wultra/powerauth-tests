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
import com.wultra.security.powerauth.test.shared.PowerAuthVaultUnlockShared;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.VaultUnlockStepModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;

/**
 * PowerAuth vault unlock tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthVaultUnlockTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_0;

    private PowerAuthTestConfiguration config;
    private PowerAuthClient powerAuthClient;
    private VaultUnlockStepModel model;
    private ObjectStepLogger stepLogger;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @BeforeEach
    void setUp() {
        model = new VaultUnlockStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setResultStatusObject(config.getResultStatusObject(VERSION));
        model.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE);
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setReason("TEST_" + VERSION);
        model.setVersion(VERSION);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void vaultUnlockTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockTest(model, stepLogger);
    }

    @Test
    void vaultUnlockInvalidPasswordTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockInvalidPasswordTest(config, model, stepLogger);
    }

    @Test
    void vaultUnlockSingleFactorTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockSingleFactorTest(config, model, stepLogger);
    }

    @Test
    void vaultUnlockBiometryFactorTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockBiometryFactorTest(model, stepLogger);
    }

    @Test
    void vaultUnlockThreeFactorTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockThreeFactorTest(model, stepLogger);
    }

    @Test
    void vaultUnlockBlockedActivationTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockBlockedActivationTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void vaultUnlockUnsupportedApplicationTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockUnsupportedApplicationTest(powerAuthClient, config, model);
    }

    @Test
    void vaultUnlockCounterIncrementTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockCounterIncrementTest(model, stepLogger);
    }

    @Test
    void vaultUnlockTooLongReasonTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockTooLongReasonTest(config, model, stepLogger);
    }

    @Test
    void vaultUnlockAndECDSASignatureValidTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockAndECDSASignatureValidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void vaultUnlockAndECDSASignatureInvalidTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockAndECDSASignatureInvalidTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void vaultUnlockAndECDSASignatureInvalidActivationTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockAndECDSASignatureInvalidActivationTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

    @Test
    void vaultUnlockAndECDSASignatureNonExistentActivationTest() throws Exception {
        PowerAuthVaultUnlockShared.vaultUnlockAndECDSASignatureNonExistentActivationTest(powerAuthClient, config, model, stepLogger, VERSION);
    }

}
