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
    void systemStatusTest() throws PowerAuthClientException {
        PowerAuthApiShared.systemStatusTest(powerAuthClient);
    }

    @Test
    void errorListTest() throws PowerAuthClientException {
        PowerAuthApiShared.errorListTest(powerAuthClient);
    }

    @Test
    void initActivationTest() throws PowerAuthClientException {
        PowerAuthApiShared.initActivationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void prepareActivationTest() throws CryptoProviderException, EncryptorException, IOException, PowerAuthClientException {
        PowerAuthApiShared.prepareActivationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void createActivationTest() throws CryptoProviderException, EncryptorException, IOException, PowerAuthClientException {
        PowerAuthApiShared.createActivationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void updateActivationOtpAndCommitTest() throws CryptoProviderException, EncryptorException, IOException, PowerAuthClientException {
        PowerAuthApiShared.updateActivationOtpAndCommitTest(powerAuthClient, config, VERSION);
    }

    @Test
    void removeActivationTest() throws PowerAuthClientException {
        PowerAuthApiShared.removeActivationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void activationListForUserTest() throws PowerAuthClientException {
        PowerAuthApiShared.activationListForUserTest(powerAuthClient, config, VERSION);
    }

    @Test
    void testGetActivationListForUserPagination() throws PowerAuthClientException {
        PowerAuthApiShared.testGetActivationListForUserPagination(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsTest() throws PowerAuthClientException {
        PowerAuthApiShared.lookupActivationsTest(powerAuthClient, config, VERSION);
    }

    @Test
    void activationStatusUpdateTest() throws PowerAuthClientException {
        PowerAuthApiShared.activationStatusUpdateTest(powerAuthClient, config, VERSION);
    }

    @Test
    void verifySignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeyException, PowerAuthClientException {
        PowerAuthApiShared.verifySignatureTest(powerAuthClient, config, VERSION);
    }

    @Test
    void nonPersonalizedOfflineSignaturePayloadTest() throws PowerAuthClientException {
        PowerAuthApiShared.nonPersonalizedOfflineSignaturePayloadTest(powerAuthClient, config);
    }

    @Test
    void personalizedOfflineSignaturePayloadTest() throws PowerAuthClientException {
        PowerAuthApiShared.personalizedOfflineSignaturePayloadTest(powerAuthClient, config, VERSION);
    }

    @Test
    void verifyOfflineSignatureTest() throws PowerAuthClientException {
        PowerAuthApiShared.verifyOfflineSignatureTest(powerAuthClient, config, VERSION);
    }

    @Test
    void unlockVaultAndECDSASignatureTest() throws GenericCryptoException, CryptoProviderException, InvalidKeySpecException, EncryptorException, IOException, InvalidKeyException, PowerAuthClientException {
        PowerAuthApiShared.unlockVaultAndECDSASignatureTest(powerAuthClient, config, VERSION);
    }

    @Test
    void activationHistoryTest() throws PowerAuthClientException {
        PowerAuthApiShared.activationHistoryTest(powerAuthClient, config, VERSION);
    }

    @Test
    void blockAndUnblockActivationTest() throws PowerAuthClientException {
        PowerAuthApiShared.blockAndUnblockActivationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void applicationListTest() throws PowerAuthClientException {
        PowerAuthApiShared.applicationListTest(powerAuthClient, config);
    }

    @Test
    void applicationDetailTest() throws PowerAuthClientException {
        PowerAuthApiShared.applicationDetailTest(powerAuthClient, config);
    }

    @Test
    void applicationVersionLookupTest() throws PowerAuthClientException {
        PowerAuthApiShared.applicationVersionLookupTest(powerAuthClient, config);
    }

    // createApplication and createApplication version tests are skipped to avoid creating too many applications

    @Test
    void applicationSupportTest() throws PowerAuthClientException {
        PowerAuthApiShared.applicationSupportTest(powerAuthClient, config);
    }

    @Test
    void applicationIntegrationTest() throws PowerAuthClientException {
        PowerAuthApiShared.applicationIntegrationTest(powerAuthClient, config);
    }

    @Test
    void callbackTest() throws PowerAuthClientException {
        PowerAuthApiShared.callbackTest(powerAuthClient, config);
    }

    @Test
    void createValidateAndRemoveTokenTestActiveActivation() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        PowerAuthApiShared.createValidateAndRemoveTokenTestActiveActivation(powerAuthClient, config, VERSION);
    }

    @Test
    void createValidateAndRemoveTokenTestBlockedActivation() throws InvalidKeySpecException, CryptoProviderException, GenericCryptoException, IOException, EncryptorException, PowerAuthClientException {
        PowerAuthApiShared.createValidateAndRemoveTokenTestBlockedActivation(powerAuthClient, config, VERSION);
    }

    @Test
    void getEciesDecryptorTest() throws EncryptorException, PowerAuthClientException {
        PowerAuthApiShared.getEciesDecryptorTest(powerAuthClient, config, VERSION);
    }

    @Test
    void recoveryCodeCreateLookupRevokeTest() throws PowerAuthClientException {
        PowerAuthApiShared.recoveryCodeCreateLookupRevokeTest(powerAuthClient, config, VERSION);
    }

    @Test
    void recoveryCodeConfirmAndActivationTest() throws CryptoProviderException, GenericCryptoException, IOException, EncryptorException, InvalidKeyException, InvalidKeySpecException, PowerAuthClientException {
        PowerAuthApiShared.recoveryCodeConfirmAndActivationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void recoveryConfigTest() throws PowerAuthClientException {
        PowerAuthApiShared.recoveryConfigTest(powerAuthClient, config);
    }

    // Activation flags are tested using PowerAuthActivationFlagsTest
    // Application roles are tested using PowerAuthApplicationRolesTest

}