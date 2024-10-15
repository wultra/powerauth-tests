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
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Test of {@link EmailConditionalValidator}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class EmailConditionalValidatorTest {

    @Mock(strictness = Mock.Strictness.LENIENT)
    private PowerAuthFido2TestsConfigProperties properties;

    @InjectMocks
    private EmailConditionalValidator tested;

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"a@b.c", "a.b-c_d@my-domain.com"})
    void testValidation_emailRequired_validExamples(final String input) {
        when(properties.isEmailAddressRequired()).thenReturn(true);
        assertTrue(isValid(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"abcd@abc", " "})
    void testValidation_emailRequired_invalidExamples(final String input) {
        when(properties.isEmailAddressRequired()).thenReturn(true);
        assertFalse(isValid(input));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"username", " ", "a@b.c"})
    void testValidation_emailNotRequired(final String input) {
        when(properties.isEmailAddressRequired()).thenReturn(false);
        assertTrue(isValid(input));
    }

    private boolean isValid(final String parameter) {
        return tested.isValid(parameter, null);
    }

}
