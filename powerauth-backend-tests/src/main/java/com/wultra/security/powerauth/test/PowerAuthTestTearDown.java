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
package com.wultra.security.powerauth.test;

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDeleteRequest;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Global test teardown.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthTestTearDown {

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    public void execute() throws PowerAuthClientException {
        // TODO - add v4
        PowerAuthVersion.VERSION_3.forEach(version -> {
            try {
                powerAuthClient.removeActivation(config.getActivationId(version), "test");
                assertTrue(config.getStatusFile(version).delete());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        removeOperationTemplates();
    }

    private void removeOperationTemplates() throws PowerAuthClientException {
        final OperationTemplateDeleteRequest request = new OperationTemplateDeleteRequest();
        request.setId(config.getLoginOperationTemplateId());
        powerAuthClient.removeOperationTemplate(request);
    }
}
