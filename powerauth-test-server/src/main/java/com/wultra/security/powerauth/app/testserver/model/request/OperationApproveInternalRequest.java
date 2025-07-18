/*
 * PowerAuth test and related software components
 * Copyright (C) 2022 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.testserver.model.request;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.wultra.security.powerauth.app.testserver.model.enumeration.SignatureType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Map;

/**
 * Request for approving an operation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class OperationApproveInternalRequest {

    @NotBlank
    private String activationId;

    @NotBlank
    private String applicationId;

    @Schema(defaultValue = "possession_knowledge")
    @JsonSetter(nulls = Nulls.SKIP)
    private SignatureType signatureType = SignatureType.POSSESSION_KNOWLEDGE;

    private String password;

    @NotBlank
    private String operationId;

    @Schema(description = "Operation data to approve.", example = "A1*A100CZK*Q238400856\\/0300**D20190629*NUtility Bill Payment - 05\\/2019")
    @NotBlank
    private String operationData;

    @Schema(description = "Optional mobile token data, structure is customer-specific. Could be used, for example, for storing FDS data.")
    private Map<String, Object> mobileTokenData;

}
