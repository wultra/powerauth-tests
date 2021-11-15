/*
 * PowerAuth Enrollment Server
 * Copyright (C) 2021 Wultra s.r.o.
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
package com.wultra.security.powerauth.model.response;

import com.wultra.security.powerauth.model.enumeration.*;
import lombok.Data;

import java.util.List;

/**
 * Response class used when checking identity document verification status.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class DocumentStatusResponse {

    private IdentityVerificationStatus status;
    private List<DocumentMetadata> documents;

    @Data
    public static class DocumentMetadata {

        private String filename;
        private String id;
        private DocumentStatus status;
        private List<String> errors;

    }

}