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

package com.wultra.security.powerauth.fido2.controller;

import com.wultra.security.powerauth.fido2.controller.request.RegisterCredentialRequest;
import com.wultra.security.powerauth.fido2.controller.request.RegistrationOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.response.RegistrationOptionsResponse;
import com.wultra.security.powerauth.fido2.model.error.PowerAuthFido2Exception;
import com.wultra.security.powerauth.fido2.model.response.RegistrationResponse;
import com.wultra.security.powerauth.fido2.service.RegistrationService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WebAuthn registration ceremony controller.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Validated
@RestController
@RequestMapping("/registration")
@AllArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping("/options")
    public RegistrationOptionsResponse options(@Valid @RequestBody final RegistrationOptionsRequest request) throws PowerAuthFido2Exception {
        return registrationService.registerOptions(request);
    }

    @PostMapping
    public RegistrationResponse register(@Valid @RequestBody final RegisterCredentialRequest request) throws PowerAuthFido2Exception {
        return registrationService.register(request);
    }

}
