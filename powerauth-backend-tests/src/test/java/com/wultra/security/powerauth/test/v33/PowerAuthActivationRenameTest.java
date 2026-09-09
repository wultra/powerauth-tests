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
package com.wultra.security.powerauth.test.v33;

import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.model.VerifyAuthenticationStepModel;
import com.wultra.security.powerauth.test.shared.v3.PowerAuthActivationRenameShared;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.HashMap;
import java.util.Map;

/**
 * PowerAuth activation rename tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthActivationRenameTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_3;

    private PowerAuthTestConfiguration config;
    private VerifyAuthenticationStepModel signatureModel;
    private ObjectStepLogger stepLogger;

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @BeforeEach
    void setUp() {
        signatureModel = new VerifyAuthenticationStepModel();
        signatureModel.setApplicationKey(config.getApplicationKey());
        signatureModel.setApplicationSecret(config.getApplicationSecret());
        signatureModel.setData(config.getObjectMapper().writeValueAsBytes(Map.of("activationName", "Test activation")));
        signatureModel.setHeaders(new HashMap<>());
        signatureModel.setHttpMethod("POST");
        signatureModel.setPassword(config.getPassword());
        signatureModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        signatureModel.setAuthenticationCodeType(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        signatureModel.setStatusFileName(config.getStatusFile(VERSION).getAbsolutePath());
        signatureModel.setBaseUriString(config.getPowerAuthIntegrationUrl());
        signatureModel.setVersion(VERSION);

        stepLogger = new ObjectStepLogger(System.out);
    }

    @Test
    void renameActivationTest() throws Exception {
        PowerAuthActivationRenameShared.renameActivationTest(config, signatureModel, stepLogger, VERSION);
    }

    @Test
    void renameActivationInvalidPasswordTest() throws Exception {
        PowerAuthActivationRenameShared.renameActivationInvalidPasswordTest(config, signatureModel, stepLogger);
    }

    @Test
    void renameActivationWeakSignatureTypeTest() throws Exception {
        PowerAuthActivationRenameShared.renameActivationWeakSignatureTypeTest(config, signatureModel, stepLogger);
    }

}
