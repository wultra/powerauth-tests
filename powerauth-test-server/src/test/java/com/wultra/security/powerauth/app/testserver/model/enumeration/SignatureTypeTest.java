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
 * Test for {@link SignatureType}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class SignatureTypeTest {

    @Test
    void testFromString_allCaps() {
        final SignatureType result = SignatureType.fromString("POSSESSION");
        assertEquals(SignatureType.POSSESSION, result);
    }

    @Test
    void testFromString_lower() {
        final SignatureType result = SignatureType.fromString("possession");
        assertEquals(SignatureType.POSSESSION, result);
    }

}