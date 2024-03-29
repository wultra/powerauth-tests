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

package com.wultra.security.powerauth.fido2.controller.response;

import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Public key credential assertion options.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Builder
public record AssertionOptionsResponse(
    String rpId,
    String challenge,
    Long timeout,
    List<CredentialDescriptor> allowCredentials,
    Map<String, Object> extensions
) {}
