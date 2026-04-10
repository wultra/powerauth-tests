/*
 * PowerAuth test and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v40;

import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.test.shared.v4.PowerAuthActivationShared;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PowerAuth activation tests.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthActivationTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V4_0;

    private PowerAuthClient powerAuthClient;
    private PowerAuthTestConfiguration config;
    private File tempStatusFile;

    enum ActivationVariant {
        EC_P384_ML_L3(SharedSecretAlgorithm.EC_P384_ML_L3, "EC_P384_ML_L3"),
        EC_P384_ML_L5(SharedSecretAlgorithm.EC_P384_ML_L5, "EC_P384_ML_L5");

        final SharedSecretAlgorithm algorithm;
        final String label;

        ActivationVariant(SharedSecretAlgorithm algorithm, String label) {
            this.algorithm = algorithm;
            this.label = label;
        }
    }

    static Stream<ActivationVariant> variants() {
        return Stream.of(ActivationVariant.EC_P384_ML_L3, ActivationVariant.EC_P384_ML_L5);
    }

    @Autowired
    public void setPowerAuthClient(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setPowerAuthTestConfiguration(PowerAuthTestConfiguration config) {
        this.config = config;
    }

    @BeforeEach
    void setUp() throws IOException {
        tempStatusFile = File.createTempFile("pa_status_" + VERSION, ".json");
    }

    @AfterEach
    void tearDown() {
        assertTrue(tempStatusFile.delete());
    }

    private PrepareActivationStepModel buildModel(ActivationVariant variant) {
        PrepareActivationStepModel model = new PrepareActivationStepModel();
        model.setActivationName("test v" + VERSION + " " + variant.label);
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKeyP384(config.getMasterPublicKeyP384());

        switch (variant) {
            case EC_P384_ML_L3 -> model.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
            case EC_P384_ML_L5 -> model.setMasterPublicKeyMlDsa87(config.getMasterPublicKeyMlDsa87());
        }

        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(new JSONObject());
        model.setUriString(config.getPowerAuthIntegrationUrl());
        model.setSharedSecretAlgorithm(variant.algorithm);
        model.setVersion(VERSION);
        model.setDeviceInfo("backend-tests");

        return model;
    }

    private PrepareActivationStepModel cloneWithAlgorithm(PrepareActivationStepModel base, SharedSecretAlgorithm algorithm) {
        Map<String, Object> map = base.toMap();
        PrepareActivationStepModel clone = new PrepareActivationStepModel();
        clone.fromMap(map);
        clone.setSharedSecretAlgorithm(algorithm);
        return clone;
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationPrepareHybridTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.activationPrepareTest(powerAuthClient, config, model, VERSION);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationPrepareEcTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PrepareActivationStepModel modelEc = cloneWithAlgorithm(model, SharedSecretAlgorithm.EC_P384);
        PowerAuthActivationShared.activationPrepareTest(powerAuthClient, config, modelEc, VERSION);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationConfirmTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);

        PowerAuthActivationShared.activationConfirmTest(powerAuthClient, config, model, VERSION, true);
        PowerAuthActivationShared.activationConfirmTest(powerAuthClient, config, model, VERSION, false);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationPrepareUnsupportedApplicationTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.activationPrepareUnsupportedApplicationTest(powerAuthClient, config, model, VERSION);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationPrepareExpirationTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.activationPrepareExpirationTest(powerAuthClient, config, model, VERSION);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationPrepareWithoutInitTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.activationPrepareWithoutInitTest(config, model);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationStatusTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.activationStatusTest(powerAuthClient, config, model, VERSION);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationInvalidApplicationKeyTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.activationInvalidApplicationKeyTest(powerAuthClient, config, model, VERSION);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void activationInvalidApplicationSecretTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.activationInvalidApplicationSecretTest(powerAuthClient, config, model, VERSION);
    }

    @ParameterizedTest
    @MethodSource("variants")
    void updateActivationStatusTest(ActivationVariant variant) throws Exception {
        PrepareActivationStepModel model = buildModel(variant);
        PowerAuthActivationShared.updateActivationStatusTest(powerAuthClient, config, model, VERSION);
    }

    @Test
    void activationNonExistentTest() throws PowerAuthClientException {
        PowerAuthActivationShared.activationNonExistentTest(powerAuthClient);
    }

    @Test
    void lookupActivationsTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsNonExistentUserTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsNonExistentUserTest(powerAuthClient);
    }

    @Test
    void lookupActivationsApplicationTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsApplicationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsNonExistentApplicationTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsNonExistentApplicationTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsStatusTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsStatusTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsInvalidStatusTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsInvalidStatusTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsDateValidTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsDateValidTest(powerAuthClient, config, VERSION);
    }

    @Test
    void lookupActivationsDateInvalidTest() throws Exception {
        PowerAuthActivationShared.lookupActivationsDateInvalidTest(powerAuthClient, config, VERSION);
    }

}
