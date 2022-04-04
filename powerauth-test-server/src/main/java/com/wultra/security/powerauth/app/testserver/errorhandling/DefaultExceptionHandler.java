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

package com.wultra.security.powerauth.app.testserver.errorhandling;

import io.getlime.core.rest.model.base.response.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception handler for RESTful API issues.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ControllerAdvice
public class DefaultExceptionHandler {

    private final static Logger logger = LoggerFactory.getLogger(DefaultExceptionHandler.class);

    /**
     * Default exception handler, for unexpected errors.
     * @param t Throwable.
     * @return Response with error details.
     */
    @ExceptionHandler(Throwable.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public @ResponseBody ErrorResponse handleDefaultException(Throwable t) {
        logger.error("Error occurred when processing the request.", t);
        return new ErrorResponse("ERROR_GENERIC", "Unknown error occurred while processing request.");
    }

    /**
     * Exception handler for application not found exception.
     * @param ex Exception.
     * @return Response with error details.
     */
    @ExceptionHandler(AppConfigNotFoundException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleApplicationNotFoundException(AppConfigNotFoundException ex) {
        logger.warn("Error occurred during application lookup.", ex);
        return new ErrorResponse("APPLICATION_NOT_FOUND", "Application was not found.");
    }

    /**
     * Exception handler for generic cryptography exception.
     * @param ex Exception.
     * @return Response with error details.
     */
    @ExceptionHandler(GenericCryptographyException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleGenericCryptographyException(GenericCryptographyException ex) {
        logger.warn("Error occurred during cryptography computation.", ex);
        return new ErrorResponse("GENERIC_CRYPTOGRAPHY_ERROR", "Generic cryptography error occurred.");
    }

    /**
     * Exception handler for remote execution exception.
     * @param ex Exception.
     * @return Response with error details.
     */
    @ExceptionHandler(RemoteExecutionException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleRemoteExecutionException(RemoteExecutionException ex) {
        logger.warn("Error occurred during remote execution.", ex);
        return new ErrorResponse("REMOTE_EXECUTION_ERROR", "Remote execution error occurred.");
    }

    /**
     * Exception handler for activation failed execution.
     * @param ex Exception.
     * @return Response with error details.
     */
    @ExceptionHandler(ActivationFailedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleActivationFailedException(ActivationFailedException ex) {
        logger.warn("Error occurred during activation.", ex);
        return new ErrorResponse("ACTIVATION_FAILED", "Activation failed.");
    }
}
