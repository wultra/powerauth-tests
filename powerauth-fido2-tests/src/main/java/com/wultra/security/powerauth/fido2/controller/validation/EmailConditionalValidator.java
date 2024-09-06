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

package com.wultra.security.powerauth.fido2.controller.validation;

import com.wultra.security.powerauth.fido2.configuration.PowerAuthFido2TestsConfigProperties;
import jakarta.validation.ConstraintValidatorContext;
import lombok.AllArgsConstructor;
import org.hibernate.validator.internal.constraintvalidators.AbstractEmailValidator;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

/**
 * Validator to validate email address. Allow null or empty values.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@AllArgsConstructor
public class EmailConditionalValidator extends AbstractEmailValidator<EmailConditional> {

    private static final Pattern GENERIC_EMAIL_PATTERN = Pattern.compile("[^@\\s]+@[^@\\s]+\\.[^@\\s]+");

    private final PowerAuthFido2TestsConfigProperties powerAuthFido2TestsConfigProperties;

    @Override
    public boolean isValid(final CharSequence value, final ConstraintValidatorContext context) {
        if (!StringUtils.hasLength(value) || !powerAuthFido2TestsConfigProperties.isEmailAddressRequired()) {
            return true;
        }

        return super.isValid(value, context) && GENERIC_EMAIL_PATTERN.matcher(value).matches();
    }

}
