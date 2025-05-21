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
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class DefaultExceptionHandler {

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
     * Exception handler for application configuration not found exception.
     * @param ex Exception.
     * @return Response with error details.
     */
    @ExceptionHandler(AppConfigNotFoundException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleAppConfigNotFoundException(AppConfigNotFoundException ex) {
        logger.warn("Error occurred during application configuration.", ex);
        return new ErrorResponse("APP_CONFIG_NOT_FOUND", "Application configuration was not found.");
    }

    /**
     * Exception handler for application configuration invalid exception.
     * @param ex Exception.
     * @return Response with error details.
     */
    @ExceptionHandler(AppConfigInvalidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleAppConfigInvalidException(AppConfigInvalidException ex) {
        logger.warn("Error occurred during application configuration.", ex);
        return new ErrorResponse("APP_CONFIG_INVALID", "Application configuration is invalid.");
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
     * Exception handler for signature verification exception.
     * @param ex Exception.
     * @return Response with error details.
     */
    @ExceptionHandler(SignatureVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public @ResponseBody ErrorResponse handleSignatureVerificationException(SignatureVerificationException ex) {
        logger.warn("Signature verification failed.", ex);
        return new ErrorResponse("SIGNATURE_VERIFICATION_EXCEPTION", "Signature verification failed.");
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
