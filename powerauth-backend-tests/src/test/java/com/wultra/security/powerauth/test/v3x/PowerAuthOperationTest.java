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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthOperationShared;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Test of PowerAuth operation endpoints.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthOperationTest {

    // Test only in the latestPowerAuth protocol version
    private static final String VERSION = "3.2";

    @Autowired
    private PowerAuthClient powerAuthClient;

    @Autowired
    private PowerAuthTestConfiguration config;

    @Test
    void testOperationApprove() throws Exception {
        PowerAuthOperationShared.testOperationApprove(powerAuthClient, config, VERSION);
    }

    @Test
    void testOperationApproveWithValidProximityOtp() throws Exception {
        PowerAuthOperationShared.testOperationApproveWithValidProximityOtp(powerAuthClient, config, VERSION);
    }

    @Test
    void testOperationApproveWithInvalidProximityOtp() throws Exception {
        PowerAuthOperationShared.testOperationApproveWithInvalidProximityOtp(powerAuthClient, config, VERSION);
    }

}
