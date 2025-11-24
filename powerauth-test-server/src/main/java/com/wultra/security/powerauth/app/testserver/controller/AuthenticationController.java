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
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeOfflineAuthRequest;
import com.wultra.security.powerauth.app.testserver.model.request.ComputeOnlineAuthRequest;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeOfflineAuthResponse;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeOnlineAuthResponse;
import com.wultra.security.powerauth.app.testserver.service.AuthenticationService;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for signature related services.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController
@Validated
@RequestMapping({"signature", "auth"})
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    /**
     * Constructor with signature service.
     * @param authenticationService Signature service.
     */
    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * Compute an online PowerAuth signature.
     * @param request Compute an online PowerAuth signature request.
     * @return Compute an online PowerAuth signature response.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws AppConfigNotFoundException In case application configuration is not found.
     */
    @PostMapping("compute-online")
    public ObjectResponse<ComputeOnlineAuthResponse> computeOnlineAuthCode(@Valid @RequestBody ObjectRequest<ComputeOnlineAuthRequest> request) throws RemoteExecutionException, ActivationFailedException, AppConfigNotFoundException {
        final ComputeOnlineAuthResponse response = authenticationService.computeOnlineAuth(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

    /**
     * Compute an offline PowerAuth signature.
     * @param request Compute an offline PowerAuth signature request.
     * @return Compute an offline PowerAuth signature response.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     */
    @PostMapping("compute-offline")
    public ObjectResponse<ComputeOfflineAuthResponse> computeOfflineSignature(@Valid @RequestBody ObjectRequest<ComputeOfflineAuthRequest> request) throws RemoteExecutionException, ActivationFailedException {
        final ComputeOfflineAuthResponse response = authenticationService.computeOfflineAuth(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

}
