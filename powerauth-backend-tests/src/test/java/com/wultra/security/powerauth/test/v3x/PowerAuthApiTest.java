/*
 * PowerAuth test and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v3x;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.test.shared.PowerAuthApiShared;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

/**
 * PowerAuth API tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthApiTest {

    private static final String VERSION = "3.2";

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @Test
    void verifySignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
        PowerAuthApiShared.verifySignatureTest(powerAuthClient, config, VERSION);
    }

    @Test
    void unlockVaultAndECDSASignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeySpecException, EncryptorException, IOException, InvalidKeyException, PowerAuthClientException {
        PowerAuthApiShared.unlockVaultAndECDSASignatureTest(powerAuthClient, config, VERSION);
    }

    // createApplication and createApplication version tests are skipped to avoid creating too many applications

    @Test
    void createValidateAndRemoveTokenTestActiveActivation() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        PowerAuthApiShared.createValidateAndRemoveTokenTestActiveActivation(powerAuthClient, config, VERSION);
    }


    @Test
    void recoveryCodeConfirmAndActivationTest() throws CryptoProviderException, GenericCryptoException, IOException, EncryptorException, InvalidKeyException, InvalidKeySpecException, PowerAuthClientException {
        PowerAuthApiShared.recoveryCodeConfirmAndActivationTest(powerAuthClient, config, VERSION);
    }

    // Activation flags are tested using PowerAuthActivationFlagsTest
    // Application roles are tested using PowerAuthApplicationRolesTest

}