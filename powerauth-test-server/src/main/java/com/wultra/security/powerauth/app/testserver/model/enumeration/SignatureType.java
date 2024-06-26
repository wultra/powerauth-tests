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

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * Enum with signature type values. For backward compatibility is not case-sensitive, see {@link #fromString(String)}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public enum SignatureType {

    /**
     * 1FA signature using possession factor key.
     */
    POSSESSION,

    /**
     * 1FA signature using knowledge factor key.
     */
    KNOWLEDGE,

    /**
     * 1FA signature using biometry factor key.
     */
    BIOMETRY,

    /**
     * 2FA signature using possession and knowledge factor key.
     */
    POSSESSION_KNOWLEDGE,

    /**
     * 2FA signature using possession and biometry factor key.
     */
    POSSESSION_BIOMETRY,

    /**
     * 3FA signature using possession, knowledge and biometry factor key.
     */
    POSSESSION_KNOWLEDGE_BIOMETRY;

    /**
     * Case-insensitive deserializer.
     *
     * @param value Value to deserialize.
     * @return signature type
     */
    @JsonCreator
    public static SignatureType fromString(String value) {
        return value == null ? null : SignatureType.valueOf(value.toUpperCase());
    }

}
