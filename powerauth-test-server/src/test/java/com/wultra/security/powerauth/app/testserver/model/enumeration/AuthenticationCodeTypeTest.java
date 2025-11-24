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
package com.wultra.security.powerauth.app.testserver.model.enumeration;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for {@link AuthenticationCodeType}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class AuthenticationCodeTypeTest {

    @Test
    void testFromString_allCaps() {
        final AuthenticationCodeType result = AuthenticationCodeType.fromString("POSSESSION");
        assertEquals(AuthenticationCodeType.POSSESSION, result);
    }

    @Test
    void testFromString_lower() {
        final AuthenticationCodeType result = AuthenticationCodeType.fromString("possession");
        assertEquals(AuthenticationCodeType.POSSESSION, result);
    }

}
