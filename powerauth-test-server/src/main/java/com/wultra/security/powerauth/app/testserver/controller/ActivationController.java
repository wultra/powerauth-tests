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

package com.wultra.security.powerauth.app.testserver.controller;

import com.wultra.security.powerauth.app.testserver.errorhandling.ActivationFailedException;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.GenericCryptographyException;
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.model.request.CreateActivationRequest;
import com.wultra.security.powerauth.app.testserver.model.response.CreateActivationResponse;
import com.wultra.security.powerauth.app.testserver.service.ActivationService;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

/**
 * Controller for activation actions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController
@RequestMapping("activation")
@Validated
public class ActivationController {

    private final ActivationService activationService;

    /**
     * Controller constructor.
     * @param activationService Activation service.
     */
    @Autowired
    public ActivationController(ActivationService activationService) {
        this.activationService = activationService;
    }

    /**
     * Create an activation.
     * @param request Create activation request.
     * @return Create activation response.
     * @throws AppConfigNotFoundException Thrown when application configuration is not found.
     * @throws GenericCryptographyException Thrown when cryptography computation fails.
     * @throws RemoteExecutionException Thrown when remote execution fails.
     * @throws ActivationFailedException Thrown when activation fails.
     */
    @PostMapping("create")
    public ObjectResponse<CreateActivationResponse> createActivation(@Valid @RequestBody ObjectRequest<CreateActivationRequest> request) throws AppConfigNotFoundException, GenericCryptographyException, RemoteExecutionException, ActivationFailedException {
        // TODO - input validation
        final CreateActivationResponse response = activationService.createActivation(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

}
