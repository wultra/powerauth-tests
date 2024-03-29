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

import java.io.Serial;

/**
 * Exception for case when cryptography computation fails.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class GenericCryptographyException extends Exception {

    @Serial
    private static final long serialVersionUID = 4520301398113031036L;

    /**
     * Default constructor.
     */
    public GenericCryptographyException() {
    }

    /**
     * Constructor with error message.
     * @param message Error message.
     */
    public GenericCryptographyException(String message) {
        super(message);
    }

    /**
     * Constructor with error message and cause.
     * @param message Error message.
     * @param cause Error cause.
     */
    public GenericCryptographyException(String message, Throwable cause) {
        super(message, cause);
    }

}
