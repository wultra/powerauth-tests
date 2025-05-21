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
package com.wultra.security.powerauth.app.testserver.model.converter;

import com.wultra.security.powerauth.app.testserver.model.enumeration.SignatureType;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

/**
 * Converter for signature types
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class SignatureTypeConverter {

    /**
     * Convert REST model to cryptographic library model.
     * @param source Signature type from REST API.
     * @return Signature type for cryptographic library.
     */
    public static PowerAuthSignatureTypes convert(final SignatureType source) {
        return switch (source) {
            case POSSESSION -> PowerAuthSignatureTypes.POSSESSION;
            case KNOWLEDGE-> PowerAuthSignatureTypes.KNOWLEDGE;
            case BIOMETRY-> PowerAuthSignatureTypes.BIOMETRY;
            case POSSESSION_KNOWLEDGE-> PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY-> PowerAuthSignatureTypes.POSSESSION_BIOMETRY;
            case POSSESSION_KNOWLEDGE_BIOMETRY-> PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY;
        };
    }

}
