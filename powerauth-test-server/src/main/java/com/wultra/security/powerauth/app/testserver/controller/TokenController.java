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
import com.wultra.security.powerauth.app.testserver.model.request.ComputeTokenDigestRequest;
import com.wultra.security.powerauth.app.testserver.model.response.ComputeTokenDigestResponse;
import com.wultra.security.powerauth.app.testserver.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.app.testserver.model.response.CreateTokenResponse;
import com.wultra.security.powerauth.app.testserver.service.TokenService;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for token related services.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController
@RequestMapping("token")
public class TokenController {

    private final TokenService tokenService;

    /**
     * Constructor with token service.
     * @param tokenService Token service.
     */
    @Autowired
    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * Call to create a new token.
     * @param request Request for creating a new token.
     * @return Response with token ID and secret.
     * @throws GenericCryptographyException In case a crypto provider is not initialized properly.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws AppConfigNotFoundException In case app configuration is incorrect.
     * @throws ActivationFailedException In case activation is not found.
     */
    @PostMapping("create")
    public ObjectResponse<CreateTokenResponse> createToken(@Valid @RequestBody ObjectRequest<CreateTokenRequest> request) throws GenericCryptographyException, RemoteExecutionException, AppConfigNotFoundException, ActivationFailedException {
        final CreateTokenResponse response = tokenService.createToken(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

    /**
     * Compute a token digest.
     * @param request Compute token digest request.
     * @return Compute token digest response.
     * @throws RemoteExecutionException In case remote communication fails.
     * @throws ActivationFailedException In case activation is not found.
     */
    @PostMapping("compute-digest")
    public ObjectResponse<ComputeTokenDigestResponse> computeTokenDigest(@Valid@RequestBody ObjectRequest<ComputeTokenDigestRequest> request) throws RemoteExecutionException, ActivationFailedException {
        final ComputeTokenDigestResponse response = tokenService.computeTokenDigest(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

}
