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

import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Controller to handle exceptions.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@ControllerAdvice
@Slf4j
public class DefaultExceptionHandler {

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ObjectResponse<PowerAuthError> handleErrors(Exception ex) {
        logger.error("Error occurred while processing the request: {}", ex.getMessage());
        logger.debug("Exception details:", ex);
        final PowerAuthError error = new PowerAuthError();
        error.setCode("ERROR");
        error.setMessage(ex.getMessage());
        error.setLocalizedMessage(ex.getLocalizedMessage());
        return new ObjectResponse<>("ERROR", error);
    }

}
