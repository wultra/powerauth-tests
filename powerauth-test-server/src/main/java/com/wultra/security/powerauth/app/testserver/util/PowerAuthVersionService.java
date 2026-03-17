/*
 * PowerAuth test and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.testserver.util;

import com.wultra.security.powerauth.app.testserver.config.TestServerConfiguration;
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * PowerAuth version conversion service.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@AllArgsConstructor
public class PowerAuthVersionService {

    private TestServerConfiguration config;

    /**
     * Map a major version to latest protocol version.
     * @param majorVersion Major version.
     * @return Latest protocol version for given major version.
     * @throws GenericCryptographyException In case the major version is not supported.
     */
    public PowerAuthVersion mapVersionToProtocol(Long majorVersion) throws GenericCryptographyException {
        if (majorVersion == null) {
            return PowerAuthVersion.fromValue(config.getVersion());
        }
        return switch (majorVersion.intValue()) {
            case 3 -> PowerAuthVersion.V3_3;
            case 4 -> PowerAuthVersion.V4_0;
            default -> throw new GenericCryptographyException("Unsupported version: " + majorVersion);
        };
    }

}
