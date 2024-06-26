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

import com.wultra.security.powerauth.fido2.controller.request.AssertionOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.request.VerifyAssertionRequest;
import com.wultra.security.powerauth.fido2.controller.response.AssertionOptionsResponse;
import com.wultra.security.powerauth.fido2.model.error.PowerAuthFido2Exception;
import com.wultra.security.powerauth.fido2.model.response.AssertionVerificationResponse;
import com.wultra.security.powerauth.fido2.service.AssertionService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WebAuthn assertion ceremony controller.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Validated
@RestController
@RequestMapping("/assertion")
@AllArgsConstructor
@Slf4j
public class AssertionController {

    final AssertionService assertionService;

    @PostMapping("/options")
    public AssertionOptionsResponse options(@Valid @RequestBody final AssertionOptionsRequest request) throws PowerAuthFido2Exception {
        return assertionService.assertionOptions(request);
    }

    @PostMapping
    public AssertionVerificationResponse verify(@Valid @RequestBody final VerifyAssertionRequest request, final HttpSession session) throws PowerAuthFido2Exception {
        final AssertionVerificationResponse response = assertionService.authenticate(request);
        if (response.isAssertionValid()) {
            session.setAttribute("userId", response.getUserId());
            session.setAttribute("applicationId", response.getApplicationId());
        }
        return response;
    }

}
