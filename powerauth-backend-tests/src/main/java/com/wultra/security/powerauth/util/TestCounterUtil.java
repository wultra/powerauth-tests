/*
 * PowerAuth test and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package com.wultra.security.powerauth.util;

import com.wultra.security.powerauth.lib.cmd.steps.pojo.ResultStatusObject;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * Utility class for working with counter.
 */
@Service
public class TestCounterUtil {

    /**
     * Get counter data from result status object.
     * @param resultStatusObject Result status object.
     * @return Counter data.
     */
    public static byte[] getCtrData(ResultStatusObject resultStatusObject) {
        String ctrDataBase64 = resultStatusObject.getCtrData();
        if (!ctrDataBase64.isEmpty()) {
            return Base64.getDecoder().decode(ctrDataBase64);
        }
        throw new IllegalStateException("Counter data is missing");
    }

}
