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

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Enum with signature type values.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public enum SignatureType {

    /**
     * 1FA signature using possession factor key, value = {@code possession}.
     */
    @JsonProperty("possession")
    POSSESSION,

    /**
     * 1FA signature using knowledge factor key, value = {@code knowledge}.
     */
    @JsonProperty("knowledge")
    KNOWLEDGE,

    /**
     * 1FA signature using biometry factor key, value = {@code biometry}.
     */
    @JsonProperty("biometry")
    BIOMETRY,

    /**
     * 2FA signature using possession and knowledge factor key, value = {@code possession_knowledge}.
     */
    @JsonProperty("possession_knowledge")
    POSSESSION_KNOWLEDGE,

    /**
     * 2FA signature using possession and biometry factor key, value = {@code possession_biometry}.
     */
    @JsonProperty("possession_biometry")
    POSSESSION_BIOMETRY,

    /**
     * 3FA signature using possession, knowledge and biometry factor key, value = {@code possession_knowledge_biometry}.
     */
    @JsonProperty("possession_knowledge_biometry")
    POSSESSION_KNOWLEDGE_BIOMETRY;
}
