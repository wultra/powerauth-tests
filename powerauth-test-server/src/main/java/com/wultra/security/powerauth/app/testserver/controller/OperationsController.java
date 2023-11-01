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

import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.app.testserver.errorhandling.ActivationFailedException;
import com.wultra.security.powerauth.app.testserver.errorhandling.AppConfigNotFoundException;
import com.wultra.security.powerauth.app.testserver.errorhandling.RemoteExecutionException;
import com.wultra.security.powerauth.app.testserver.errorhandling.SignatureVerificationException;
import com.wultra.security.powerauth.app.testserver.model.request.GetOperationsRequest;
import com.wultra.security.powerauth.app.testserver.model.request.OperationApproveInternalRequest;
import com.wultra.security.powerauth.app.testserver.service.OperationsService;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.lib.mtoken.model.response.OperationListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for operation specific services.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController
@RequestMapping("operations")
public class OperationsController {

    private final OperationsService operationsService;

    /**
     * Constructor with operation service.
     * @param operationsService Operation service.
     */
    @Autowired
    public OperationsController(OperationsService operationsService) {
        this.operationsService = operationsService;
    }

    /**
     * Obtain pending operations.
     * @param request Request to obtain pending operations.
     * @return Response with pending operations.
     * @throws RemoteExecutionException In case internal calls fail.
     * @throws RestClientException In case REST client call fails (fetching operations).
     * @throws SignatureVerificationException In case signature verification fails.
     * @throws ActivationFailedException In case activation is not found.
     */
    @PostMapping("pending")
    public ObjectResponse<OperationListResponse> fetchOperations(@RequestBody ObjectRequest<GetOperationsRequest> request) throws RemoteExecutionException, RestClientException, SignatureVerificationException, ActivationFailedException {
        final OperationListResponse response = operationsService.getOperations(request.getRequestObject());
        return new ObjectResponse<>(response);
    }

    /**
     * Approve operation with given ID and data.
     * @param request Operation approval request.
     * @return Response with operation approval result.
     * @throws RemoteExecutionException In case internal calls fail.
     * @throws SignatureVerificationException In case signature verification fails.
     * @throws ActivationFailedException In case activation is not found.
     * @throws AppConfigNotFoundException In case app configuration is not found.
     */
    @PostMapping("approve")
    public Response approveOperations(@RequestBody ObjectRequest<OperationApproveInternalRequest> request) throws RemoteExecutionException, AppConfigNotFoundException, SignatureVerificationException, ActivationFailedException {
        return operationsService.approveOperation(request.getRequestObject());
    }

}
