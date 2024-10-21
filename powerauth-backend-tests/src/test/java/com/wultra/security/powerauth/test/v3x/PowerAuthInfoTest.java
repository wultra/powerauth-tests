/*
 * PowerAuth test and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthInfoShared;
import io.getlime.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import io.getlime.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.EnabledIf;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;

/**
 * Test for {@code /pa/v3/user/info}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
@EnabledIf(expression = "${powerauth.test.includeCustomTests}", loadContext = true)
class PowerAuthInfoTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_3;

    @Autowired
    private PowerAuthTestConfiguration config;

    private EncryptStepModel encryptModel;

    @BeforeEach
    void setUp() {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKey(config.getMasterPublicKey());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        encryptModel.setBaseUriString(config.getPowerAuthIntegrationUrl());
        encryptModel.setVersion(VERSION);
    }

    @Test
    void testUserInfo() throws Exception {
        PowerAuthInfoShared.testUserInfo(config, encryptModel, VERSION);
    }

    @Test
    void testServerStatus() throws Exception {
        PowerAuthInfoShared.testServerStatus(config);
    }

}
