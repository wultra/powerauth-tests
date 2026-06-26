/*
 * PowerAuth test and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.v4x;

import com.wultra.security.powerauth.client.model.enumeration.ConfigScope;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreateConfigItemRequest;
import com.wultra.security.powerauth.client.model.request.v4.GetConfigItemsRequest;
import com.wultra.security.powerauth.client.model.request.v4.RemoveConfigItemRequest;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetConfigItemsResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.logging.model.StepItem;
import com.wultra.security.powerauth.lib.cmd.steps.ConfirmActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.EncryptStep;
import com.wultra.security.powerauth.lib.cmd.steps.PrepareActivationStep;
import com.wultra.security.powerauth.lib.cmd.steps.model.ConfirmActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.EncryptStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.model.PrepareActivationStepModel;
import com.wultra.security.powerauth.rest.api.model.entity.ConfigItem;
import com.wultra.security.powerauth.rest.api.model.response.v4.ConfigResponse;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opentest4j.AssertionFailedError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the secure configuration delivered over end-to-end encryption through the enrollment server
 * ({@code POST /pa/v4/config/application} and {@code POST /pa/v4/config/activation}).
 * <p>
 * Configuration items are created and removed via the PowerAuth server management REST API (V4), and then
 * fetched over E2EE to verify eligibility, scope tagging, and cross-scope precedence across all scope and
 * endpoint combinations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthConfigStoreTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V4_0;

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder().build();

    /** Alias to avoid the long FQN every time the SDK-side {@code ConfigScope} is referenced. */
    private static final com.wultra.security.powerauth.rest.api.model.entity.ConfigScope SCOPE_APPLICATION =
            com.wultra.security.powerauth.rest.api.model.entity.ConfigScope.APPLICATION;
    private static final com.wultra.security.powerauth.rest.api.model.entity.ConfigScope SCOPE_ACTIVATION =
            com.wultra.security.powerauth.rest.api.model.entity.ConfigScope.ACTIVATION;

    @Autowired
    private PowerAuthTestConfiguration config;

    @Autowired
    private PowerAuthClient powerAuthClient;

    private EncryptStepModel encryptModel;

    @BeforeEach
    void setUp() {
        encryptModel = new EncryptStepModel();
        encryptModel.setApplicationKey(config.getApplicationKey());
        encryptModel.setApplicationSecret(config.getApplicationSecret());
        encryptModel.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
        encryptModel.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
        encryptModel.setHeaders(new HashMap<>());
        encryptModel.setResultStatusObject(config.getResultStatusObject(VERSION));
        encryptModel.setBaseUriString(config.getPowerAuthIntegrationUrl());
        encryptModel.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        encryptModel.setVersion(VERSION);
    }

    @Test
    void applicationScopeVisibilityTest() throws Exception {
        // APPLICATION-scope items must be visible at both the application and activation endpoints,
        // and the scope tag must be APPLICATION in both cases.
        final String key = uniqueKey();
        final String value = "https://api.example.com";
        createConfig(ConfigScope.APPLICATION, null, key, value);
        try {
            final ConfigResponse applicationResponse = fetchConfig("application");
            final ConfigItem viaApplication = findItem(applicationResponse, key);
            assertNotNull(viaApplication, "APPLICATION-scope item must be visible via the application endpoint");
            assertEquals(SCOPE_APPLICATION, viaApplication.scope());
            assertEquals(value, viaApplication.value());

            // Invariant of the application endpoint: every item returned must carry APPLICATION scope.
            // No ACTIVATION-scope item may ever leak here, regardless of how the server resolves the merge.
            applicationResponse.config().forEach(item ->
                    assertEquals(SCOPE_APPLICATION, item.scope(),
                            "Application endpoint must only return APPLICATION-scope items, but key '"
                                    + item.key() + "' has scope " + item.scope()));

            final ConfigItem viaActivation = findItem(fetchConfig("activation"), key);
            assertNotNull(viaActivation, "APPLICATION-scope item must also be visible via the activation endpoint");
            assertEquals(SCOPE_APPLICATION, viaActivation.scope());
            assertEquals(value, viaActivation.value());
        } finally {
            removeConfig(ConfigScope.APPLICATION, null, key);
        }
    }

    @Test
    void activationAppWideScopeVisibilityTest() throws Exception {
        // App-wide ACTIVATION-scope items must be visible at the activation endpoint but must NOT
        // leak to the application endpoint, which is restricted to APPLICATION-scope items only.
        final String key = uniqueKey();
        final String value = "activation-scoped-value";
        createConfig(ConfigScope.ACTIVATION, null, key, value);
        try {
            final ConfigItem viaActivation = findItem(fetchConfig("activation"), key);
            assertNotNull(viaActivation, "App-wide ACTIVATION-scope item must be visible via the activation endpoint");
            assertEquals(SCOPE_ACTIVATION, viaActivation.scope());
            assertEquals(value, viaActivation.value());

            final ConfigItem viaApplication = findItem(fetchConfig("application"), key);
            assertNull(viaApplication, "App-wide ACTIVATION-scope item must not leak to the application endpoint");
        } finally {
            removeConfig(ConfigScope.ACTIVATION, null, key);
        }
    }

    @Test
    void perDeviceScopeVisibilityTest() throws Exception {
        // Per-device (activationId-scoped) ACTIVATION items must be visible at the activation endpoint
        // for the owning activation, must not leak to the application endpoint, and must faithfully
        // round-trip object-typed values through E2EE.
        final String activationId = config.getActivationId(VERSION);
        final String key = uniqueKey();
        final Map<String, Object> value = Map.of("url", "https://device.example.com", "timeout", 30);
        createConfig(ConfigScope.ACTIVATION, activationId, key, value);
        try {
            final ConfigItem viaActivation = findItem(fetchConfig("activation"), key);
            assertNotNull(viaActivation, "Per-device item must be visible via the activation endpoint");
            assertEquals(SCOPE_ACTIVATION, viaActivation.scope());
            assertInstanceOf(Map.class, viaActivation.value(), "Object value must be deserialized as a Map");
            assertEquals("https://device.example.com", ((Map<?, ?>) viaActivation.value()).get("url"));
            assertEquals(30, ((Number) ((Map<?, ?>) viaActivation.value()).get("timeout")).intValue());

            assertNull(findItem(fetchConfig("application"), key),
                    "Per-device item must not be visible via the application endpoint");
        } finally {
            removeConfig(ConfigScope.ACTIVATION, activationId, key);
        }
    }

    @Test
    void crossScopePrecedencePerDeviceWinsTest() throws Exception {
        final String activationId = config.getActivationId(VERSION);
        final String key = uniqueKey();
        final String applicationValue = "https://app.example.com";
        final String deviceValue = "https://device-override.example.com";
        createConfig(ConfigScope.APPLICATION, null, key, applicationValue);
        createConfig(ConfigScope.ACTIVATION, activationId, key, deviceValue);
        try {
            // Activation endpoint: the more specific per-device value wins, and the key appears exactly once.
            final ConfigResponse activationResponse = fetchConfig("activation");
            final List<ConfigItem> activationMatches = activationResponse.config().stream()
                    .filter(it -> key.equals(it.key()))
                    .toList();
            assertEquals(1, activationMatches.size(), "The key must be resolved to a single effective value");
            assertEquals(deviceValue, activationMatches.get(0).value());
            assertEquals(SCOPE_ACTIVATION, activationMatches.get(0).scope());

            // Application endpoint: only the application-scope value is visible.
            final ConfigItem applicationItem = findItem(fetchConfig("application"), key);
            assertNotNull(applicationItem);
            assertEquals(applicationValue, applicationItem.value());
            assertEquals(SCOPE_APPLICATION, applicationItem.scope());
        } finally {
            removeConfig(ConfigScope.ACTIVATION, activationId, key);
            removeConfig(ConfigScope.APPLICATION, null, key);
        }
    }

    @Test
    void removedItemNotReturnedTest() throws Exception {
        final String key = uniqueKey();
        final String value = "https://temporary.example.com";
        createConfig(ConfigScope.APPLICATION, null, key, value);
        boolean removed = false;
        try {
            assertNotNull(findItem(fetchConfig("application"), key), "Item must be present before removal");
            removeConfig(ConfigScope.APPLICATION, null, key);
            removed = true;
            assertNull(findItem(fetchConfig("application"), key), "Item must not be returned after removal");
        } finally {
            if (!removed) {
                removeConfig(ConfigScope.APPLICATION, null, key);
            }
        }
    }

    @Test
    void scopePrecedenceLifecycleTest() throws Exception {
        // This test walks through the full lifecycle of scope precedence for a single key:
        //   APPLICATION configured → ACTIVATION overrides → ACTIVATION removed → APPLICATION restored → APPLICATION removed → gone.
        final String key = uniqueKey();
        final String applicationValue = "https://app-scope.example.com";
        final String activationValue = "https://activation-scope.example.com";

        // Step 1: Configure the key at APPLICATION scope and verify it is visible via the activation endpoint.
        createConfig(ConfigScope.APPLICATION, null, key, applicationValue);
        try {
            final ConfigItem afterAppCreate = findItem(fetchConfig("activation"), key);
            assertNotNull(afterAppCreate, "APPLICATION-scope item must be visible via the activation endpoint");
            assertEquals(applicationValue, afterAppCreate.value(), "Value must match the APPLICATION-scope entry");
            assertEquals(SCOPE_APPLICATION, afterAppCreate.scope());

            // Step 2: Add the same key at ACTIVATION scope (app-wide) — the more specific scope must win.
            createConfig(ConfigScope.ACTIVATION, null, key, activationValue);
            try {
                final ConfigItem afterActivationCreate = findItem(fetchConfig("activation"), key);
                assertNotNull(afterActivationCreate, "Key must still be visible after ACTIVATION-scope entry is added");
                assertEquals(activationValue, afterActivationCreate.value(),
                        "ACTIVATION-scope value must take precedence over APPLICATION-scope value for the same key");
                assertEquals(SCOPE_ACTIVATION, afterActivationCreate.scope());

                // Verify the APPLICATION endpoint is unaffected — it still returns only the APPLICATION-scope entry.
                final ConfigItem appEndpointItem = findItem(fetchConfig("application"), key);
                assertNotNull(appEndpointItem);
                assertEquals(applicationValue, appEndpointItem.value(),
                        "APPLICATION endpoint must still return the APPLICATION-scope value");
                assertEquals(SCOPE_APPLICATION, appEndpointItem.scope());

                // Step 3: Remove the ACTIVATION-scope entry — the APPLICATION-scope value must re-emerge.
                removeConfig(ConfigScope.ACTIVATION, null, key);
                final ConfigItem afterActivationRemove = findItem(fetchConfig("activation"), key);
                assertNotNull(afterActivationRemove, "APPLICATION-scope item must be visible again after ACTIVATION-scope entry is removed");
                assertEquals(applicationValue, afterActivationRemove.value(),
                        "Fallback to APPLICATION-scope value must occur after the ACTIVATION-scope entry is removed");
                assertEquals(SCOPE_APPLICATION, afterActivationRemove.scope());
            } finally {
                // Guard: clean up ACTIVATION-scope entry if step 3 did not run (e.g. assertion failure in step 2).
                removeConfig(ConfigScope.ACTIVATION, null, key);
            }

            // Step 4: Remove the APPLICATION-scope entry — no value must be returned for the key.
            removeConfig(ConfigScope.APPLICATION, null, key);
            final ConfigItem afterAppRemove = findItem(fetchConfig("activation"), key);
            assertNull(afterAppRemove, "No value must be returned after both scope entries are removed");
        } finally {
            // Guard: ensure APPLICATION-scope entry is removed even when the test fails early.
            removeConfig(ConfigScope.APPLICATION, null, key);        }
    }

    @Test
    void updateValueWhileShadowedByScopeTest() throws Exception {
        // Verifies that updating a lower-tier entry while it is shadowed by a higher-tier entry
        // does not change what the SDK sees, but correctly restores the updated value once the
        // shadow is removed.
        //
        // Sequence:
        //   1. Create APPLICATION entry (valueA).
        //   2. Create ACTIVATION entry with same key (valueB) → ACTIVATION shadows APPLICATION.
        //   3. Update APPLICATION entry to valueA' while it is still shadowed → activation endpoint still returns valueB.
        //   4. Update ACTIVATION entry to valueB' → activation endpoint now returns valueB'.
        //   5. Remove ACTIVATION entry → activation endpoint now returns the updated APPLICATION value (valueA').
        //   6. Remove APPLICATION entry → key is gone.
        final String key = uniqueKey();
        final String valueA = "https://original-app.example.com";
        final String valueAUpdated = "https://updated-app.example.com";
        final String valueB = "https://original-act.example.com";
        final String valueBUpdated = "https://updated-act.example.com";

        createConfig(ConfigScope.APPLICATION, null, key, valueA);
        try {
            final ConfigItem step1 = findItem(fetchConfig("activation"), key);
            assertNotNull(step1, "Step 1: Key must be returned initially");
            assertEquals(valueA, step1.value(), "Step 1: APPLICATION value must be returned initially");
            createConfig(ConfigScope.ACTIVATION, null, key, valueB);
            try {
                assertEquals(valueB, findItem(fetchConfig("activation"), key).value(),
                        "Step 2: ACTIVATION value must shadow APPLICATION value");

                // Step 3: Update APPLICATION value while it is still shadowed.
                createConfig(ConfigScope.APPLICATION, null, key, valueAUpdated);
                assertEquals(valueB, findItem(fetchConfig("activation"), key).value(),
                        "Step 3: ACTIVATION value must still win after APPLICATION value is updated in the background");
                assertEquals(valueAUpdated, findItem(fetchConfig("application"), key).value(),
                        "Step 3: Updated APPLICATION value must be immediately visible via the application endpoint");

                // Step 4: Update ACTIVATION value — new ACTIVATION value must be immediately visible.
                createConfig(ConfigScope.ACTIVATION, null, key, valueBUpdated);
                assertEquals(valueBUpdated, findItem(fetchConfig("activation"), key).value(),
                        "Step 4: Updated ACTIVATION value must be returned via the activation endpoint");
                assertEquals(valueAUpdated, findItem(fetchConfig("application"), key).value(),
                        "Step 4: APPLICATION endpoint must remain unaffected by the ACTIVATION update");

                // Step 5: Remove ACTIVATION entry → updated APPLICATION value must surface.
                removeConfig(ConfigScope.ACTIVATION, null, key);
                final ConfigItem restored = findItem(fetchConfig("activation"), key);
                assertNotNull(restored, "Step 5: APPLICATION entry must surface after ACTIVATION shadow is removed");
                assertEquals(valueAUpdated, restored.value(),
                        "Step 5: The updated APPLICATION value must be returned, not the stale original");
                assertEquals(SCOPE_APPLICATION, restored.scope());
            } finally {
                removeConfig(ConfigScope.ACTIVATION, null, key);
            }
            removeConfig(ConfigScope.APPLICATION, null, key);
            assertNull(findItem(fetchConfig("activation"), key), "Step 6: Key must be absent after all entries are removed");
            assertNull(findItem(fetchConfig("application"), key), "Step 6: Key must also be absent from the application endpoint");
        } finally {
            removeConfig(ConfigScope.APPLICATION, null, key);
        }
    }

    @Test
    void multipleKeysWithMixedScopesTest() throws Exception {
        // Creates several keys with different scope combinations simultaneously and verifies that
        // each endpoint returns exactly the right set of items — no leakage, no missing entries.
        //
        // Key matrix:
        //   keyAppOnly   — APPLICATION scope only            → application endpoint: present; activation endpoint: present (APPLICATION value)
        //   keyActOnly   — ACTIVATION scope (app-wide) only  → application endpoint: absent;  activation endpoint: present (ACTIVATION value)
        //   keyBothScopes— APPLICATION + ACTIVATION (app-wide)→ application endpoint: APPLICATION value; activation endpoint: ACTIVATION value (wins)
        //   keyPerDevice — per-device ACTIVATION only        → application endpoint: absent;  activation endpoint: present (per-device value)
        final String activationId = config.getActivationId(VERSION);
        final String keyAppOnly = uniqueKey();
        final String keyActOnly = uniqueKey();
        final String keyBothScopes = uniqueKey();
        final String keyPerDevice = uniqueKey();
        final String valueAppOnly = "app-only-value";
        final String valueActOnly = "act-only-value";
        final String valueBothApp = "both-app-value";
        final String valueBothAct = "both-act-value";
        final String valuePerDevice = "per-device-value";

        createConfig(ConfigScope.APPLICATION, null, keyAppOnly, valueAppOnly);
        createConfig(ConfigScope.ACTIVATION, null, keyActOnly, valueActOnly);
        createConfig(ConfigScope.APPLICATION, null, keyBothScopes, valueBothApp);
        createConfig(ConfigScope.ACTIVATION, null, keyBothScopes, valueBothAct);
        createConfig(ConfigScope.ACTIVATION, activationId, keyPerDevice, valuePerDevice);
        try {
            // --- Activation endpoint ---
            final ConfigResponse activationResponse = fetchConfig("activation");

            final ConfigItem itemAppOnly = findItem(activationResponse, keyAppOnly);
            assertNotNull(itemAppOnly, "APPLICATION-only key must be visible via activation endpoint");
            assertEquals(valueAppOnly, itemAppOnly.value());
            assertEquals(SCOPE_APPLICATION, itemAppOnly.scope());

            final ConfigItem itemActOnly = findItem(activationResponse, keyActOnly);
            assertNotNull(itemActOnly, "ACTIVATION-only key must be visible via activation endpoint");
            assertEquals(valueActOnly, itemActOnly.value());
            assertEquals(SCOPE_ACTIVATION, itemActOnly.scope());

            final ConfigItem itemBothViaActivation = findItem(activationResponse, keyBothScopes);
            assertNotNull(itemBothViaActivation, "Dual-scope key must be visible via activation endpoint");
            assertEquals(valueBothAct, itemBothViaActivation.value(),
                    "ACTIVATION value must win over APPLICATION value for the same key at the activation endpoint");
            assertEquals(SCOPE_ACTIVATION, itemBothViaActivation.scope());
            // The key must appear exactly once in the activation response.
            assertEquals(1, activationResponse.config().stream().filter(it -> keyBothScopes.equals(it.key())).count(),
                    "Dual-scope key must appear exactly once in the activation response (lower tier suppressed)");

            final ConfigItem itemPerDevice = findItem(activationResponse, keyPerDevice);
            assertNotNull(itemPerDevice, "Per-device key must be visible via activation endpoint");
            assertEquals(valuePerDevice, itemPerDevice.value());
            assertEquals(SCOPE_ACTIVATION, itemPerDevice.scope());

            // --- Application endpoint ---
            final ConfigResponse applicationResponse = fetchConfig("application");

            assertNotNull(findItem(applicationResponse, keyAppOnly),
                    "APPLICATION-only key must be visible via application endpoint");
            assertEquals(valueAppOnly, findItem(applicationResponse, keyAppOnly).value());

            assertNull(findItem(applicationResponse, keyActOnly),
                    "ACTIVATION-only key must NOT be visible via application endpoint");

            final ConfigItem itemBothViaApplication = findItem(applicationResponse, keyBothScopes);
            assertNotNull(itemBothViaApplication, "Dual-scope key must be visible via application endpoint");
            assertEquals(valueBothApp, itemBothViaApplication.value(),
                    "APPLICATION value must be returned at the application endpoint regardless of any ACTIVATION entry");
            assertEquals(SCOPE_APPLICATION, itemBothViaApplication.scope());

            assertNull(findItem(applicationResponse, keyPerDevice),
                    "Per-device key must NOT be visible via application endpoint");
        } finally {
            removeConfig(ConfigScope.APPLICATION, null, keyAppOnly);
            removeConfig(ConfigScope.ACTIVATION, null, keyActOnly);
            removeConfig(ConfigScope.APPLICATION, null, keyBothScopes);
            removeConfig(ConfigScope.ACTIVATION, null, keyBothScopes);
            removeConfig(ConfigScope.ACTIVATION, activationId, keyPerDevice);
        }
    }

    @Test
    void perDeviceValueLifecycleWithFallbackTest() throws Exception {
        // Mirrors scopePrecedenceLifecycleTest but for the per-device (activationId-scoped) tier,
        // verifying the full lifecycle of a per-device override on top of an APPLICATION base value.
        //
        // Sequence:
        //   1. Create APPLICATION entry → activation endpoint returns APPLICATION value.
        //   2. Create per-device ACTIVATION entry → activation endpoint returns per-device value.
        //   3. Update per-device entry to a new value → activation endpoint returns the new per-device value.
        //   4. Remove per-device entry → activation endpoint falls back to APPLICATION value.
        //   5. Remove APPLICATION entry → key is completely absent.
        final String activationId = config.getActivationId(VERSION);
        final String key = uniqueKey();
        final String applicationValue = "https://base-app.example.com";
        final String perDeviceValue = "https://per-device-v1.example.com";
        final String perDeviceUpdated = "https://per-device-v2.example.com";

        createConfig(ConfigScope.APPLICATION, null, key, applicationValue);
        try {
            // Step 1: APPLICATION base value is visible at the activation endpoint.
            final ConfigItem step1 = findItem(fetchConfig("activation"), key);
            assertNotNull(step1);
            assertEquals(applicationValue, step1.value(), "Step 1: APPLICATION base value must be returned");
            assertEquals(SCOPE_APPLICATION, step1.scope());
            // Not visible at the application endpoint for the per-device path (yet), but visible as APPLICATION.
            assertNotNull(findItem(fetchConfig("application"), key), "Step 1: Key must be visible at the application endpoint too");

            createConfig(ConfigScope.ACTIVATION, activationId, key, perDeviceValue);
            try {
                // Step 2: Per-device entry shadows the APPLICATION base value.
                final ConfigItem step2 = findItem(fetchConfig("activation"), key);
                assertNotNull(step2);
                assertEquals(perDeviceValue, step2.value(), "Step 2: Per-device value must shadow APPLICATION value");
                assertEquals(SCOPE_ACTIVATION, step2.scope());
                // Per-device entry must NOT leak to the application endpoint.
                final ConfigItem appEndpointStep2 = findItem(fetchConfig("application"), key);
                assertNotNull(appEndpointStep2, "Step 2: APPLICATION entry must still be visible via application endpoint");
                assertEquals(applicationValue, appEndpointStep2.value(),
                        "Step 2: Application endpoint must return the APPLICATION value, not the per-device value");

                // Step 3: Update per-device entry to a new value.
                createConfig(ConfigScope.ACTIVATION, activationId, key, perDeviceUpdated);
                final ConfigItem step3 = findItem(fetchConfig("activation"), key);
                assertNotNull(step3);
                assertEquals(perDeviceUpdated, step3.value(), "Step 3: Updated per-device value must be returned");
                assertEquals(SCOPE_ACTIVATION, step3.scope());
                assertEquals(applicationValue, findItem(fetchConfig("application"), key).value(),
                        "Step 3: APPLICATION endpoint must still return the APPLICATION value");

                // Step 4: Remove per-device entry → APPLICATION base value must surface.
                removeConfig(ConfigScope.ACTIVATION, activationId, key);
                final ConfigItem step4 = findItem(fetchConfig("activation"), key);
                assertNotNull(step4, "Step 4: APPLICATION base value must surface after per-device entry is removed");
                assertEquals(applicationValue, step4.value(),
                        "Step 4: APPLICATION value must be the effective value once per-device entry is removed");
                assertEquals(SCOPE_APPLICATION, step4.scope());
            } finally {
                removeConfig(ConfigScope.ACTIVATION, activationId, key);
            }

            // Step 5: Remove APPLICATION entry → key must disappear entirely.
            removeConfig(ConfigScope.APPLICATION, null, key);
            assertNull(findItem(fetchConfig("activation"), key), "Step 5: Key must be absent after all entries are removed");
            assertNull(findItem(fetchConfig("application"), key), "Step 5: Key must also be absent from the application endpoint");
        } finally {
            removeConfig(ConfigScope.APPLICATION, null, key);
        }
    }

    @Test
    void objectValueLifecycleTest() throws Exception {
        // Verifies that the value shape can freely change between types (scalar → nested object → scalar)
        // across successive updates, and that the full object is faithfully round-tripped through E2EE.
        final String key = uniqueKey();
        final String scalarValue = "https://scalar.example.com";
        final Map<String, Object> objectValue = Map.of(
                "url", "https://nested.example.com",
                "timeout", 30,
                "retries", 3,
                "metadata", Map.of("env", "test", "region", "eu-west-1")
        );
        final String updatedScalar = "https://updated-scalar.example.com";

        createConfig(ConfigScope.APPLICATION, null, key, scalarValue);
        try {
            // Scalar value round-trips correctly.
            final ConfigItem afterScalar = findItem(fetchConfig("application"), key);
            assertNotNull(afterScalar);
            assertEquals(scalarValue, afterScalar.value(), "Scalar value must be returned unchanged");

            // Overwrite with a nested object — all fields must survive the E2EE round-trip.
            createConfig(ConfigScope.APPLICATION, null, key, objectValue);
            final ConfigItem afterObject = findItem(fetchConfig("application"), key);
            assertNotNull(afterObject, "Object-typed value must be retrievable via the application endpoint");
            assertInstanceOf(Map.class, afterObject.value(), "Value must be deserialized as a Map");
            final Map<?, ?> returned = (Map<?, ?>) afterObject.value();
            assertEquals("https://nested.example.com", returned.get("url"), "String field in object must be preserved");
            assertEquals(30, ((Number) returned.get("timeout")).intValue(), "Integer field in object must be preserved");
            assertEquals(3, ((Number) returned.get("retries")).intValue(), "Integer field in object must be preserved");
            assertInstanceOf(Map.class, returned.get("metadata"), "Nested map must be preserved");
            assertEquals("eu-west-1", ((Map<?, ?>) returned.get("metadata")).get("region"),
                    "Deeply nested field must be preserved");

            // Also visible at the activation endpoint.
            final ConfigItem viaActivation = findItem(fetchConfig("activation"), key);
            assertNotNull(viaActivation, "Object value must also be visible via the activation endpoint");
            assertInstanceOf(Map.class, viaActivation.value());

            // Overwrite back to a scalar — object must be completely replaced.
            createConfig(ConfigScope.APPLICATION, null, key, updatedScalar);
            final ConfigItem afterUpdatedScalar = findItem(fetchConfig("application"), key);
            assertNotNull(afterUpdatedScalar);
            assertEquals(updatedScalar, afterUpdatedScalar.value(),
                    "Scalar value must replace the previous object value");
            assertFalse(afterUpdatedScalar.value() instanceof Map,
                    "Previous object must not leak into the new scalar value");
        } finally {
            removeConfig(ConfigScope.APPLICATION, null, key);
        }
    }

    @Test
    void updateConfigItemValueTest() throws Exception {
        final String key = uniqueKey();
        final String initialValue = "https://initial.example.com";
        final String updatedValue = "https://updated.example.com";
        createConfig(ConfigScope.APPLICATION, null, key, initialValue);
        try {
            final ConfigItem itemBefore = findItem(fetchConfig("application"), key);
            assertNotNull(itemBefore, "Item must be present after initial creation");
            assertEquals(initialValue, itemBefore.value());

            // createConfig is idempotent "create or update" — calling again with the same key overwrites the value.
            createConfig(ConfigScope.APPLICATION, null, key, updatedValue);

            final ConfigItem itemAfter = findItem(fetchConfig("application"), key);
            assertNotNull(itemAfter, "Item must still be present after update");
            assertEquals(updatedValue, itemAfter.value(), "Updated value must be returned via the E2EE endpoint");
            assertEquals(SCOPE_APPLICATION, itemAfter.scope());
        } finally {
            removeConfig(ConfigScope.APPLICATION, null, key);
        }
    }


    @Test
    void perDeviceItemNotVisibleToOtherActivationTest() throws Exception {
        final String mainActivationId = config.getActivationId(VERSION);
        final String key = uniqueKey();
        // Bind a per-device config item to the main test activation.
        createConfig(ConfigScope.ACTIVATION, mainActivationId, key, "secret-for-main-activation-only");

        final File secondStatusFile = File.createTempFile("pa_status_second_", ".json");
        final JSONObject secondStatusObject = new JSONObject();
        String secondActivationId = null;
        try {
            secondActivationId = initAndActivate(secondStatusFile, secondStatusObject);
            final EncryptStepModel secondEncryptModel = buildEncryptModelForActivation(secondStatusObject);

            // The per-device item of the main activation must NOT be visible when fetching via a different activation.
            final ConfigResponse secondResponse = fetchConfig(secondEncryptModel, "activation");
            assertNull(findItem(secondResponse, key),
                    "Per-device config of activation A must not be visible when fetching with activation B");
        } finally {
            removeConfig(ConfigScope.ACTIVATION, mainActivationId, key);
            if (secondActivationId != null) {
                powerAuthClient.removeActivation(secondActivationId, "test");
            }
            assertTrue(secondStatusFile.delete());
        }
    }

    @Test
    void activationEndpointRejectsApplicationScopeEncryptionTest() throws Exception {
        // The activation endpoint must reject requests encrypted with application-scope ECIES,
        // because without the activation-level session key the server cannot determine which activation
        // the request belongs to and therefore cannot return per-device configuration items.
        final EncryptStepModel appScopeModel = new EncryptStepModel();
        appScopeModel.setApplicationKey(config.getApplicationKey());
        appScopeModel.setApplicationSecret(config.getApplicationSecret());
        appScopeModel.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
        appScopeModel.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
        appScopeModel.setHeaders(new HashMap<>());
        appScopeModel.setResultStatusObject(new JSONObject());
        appScopeModel.setBaseUriString(config.getPowerAuthIntegrationUrl());
        appScopeModel.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        appScopeModel.setVersion(VERSION);
        appScopeModel.setUriString(config.getEnrollmentServiceUrl() + "/pa/v4/config/activation");
        appScopeModel.setScope("application");
        appScopeModel.setData("{}".getBytes(StandardCharsets.UTF_8));

        final ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new EncryptStep().execute(stepLogger, appScopeModel.toMap());
        assertFalse(stepLogger.getResult().success(),
                "The activation endpoint must reject application-scope ECIES (no activation context)");
    }

    @Test
    void appWideActivationScopeVisibleToOtherActivationsTest() throws Exception {
        // App-wide ACTIVATION-scope items (no activationId) must be visible to ALL activations of the
        // application, not just the one used to provision them. This verifies the "app-wide" semantics.
        final String key = uniqueKey();
        final String value = "shared-across-activations";
        createConfig(ConfigScope.ACTIVATION, null, key, value);

        final File secondStatusFile = File.createTempFile("pa_status_appwide_", ".json");
        final JSONObject secondStatusObject = new JSONObject();
        String secondActivationId = null;
        try {
            // The primary test activation must see it.
            final ConfigItem viaPrimary = findItem(fetchConfig("activation"), key);
            assertNotNull(viaPrimary, "App-wide ACTIVATION-scope item must be visible via the primary activation");
            assertEquals(value, viaPrimary.value());
            assertEquals(SCOPE_ACTIVATION, viaPrimary.scope());

            // And so must an independent, freshly-activated device.
            secondActivationId = initAndActivate(secondStatusFile, secondStatusObject);
            final EncryptStepModel secondEncryptModel = buildEncryptModelForActivation(secondStatusObject);
            final ConfigItem viaSecond = findItem(fetchConfig(secondEncryptModel, "activation"), key);
            assertNotNull(viaSecond, "App-wide ACTIVATION-scope item must be visible via a second activation as well");
            assertEquals(value, viaSecond.value());
            assertEquals(SCOPE_ACTIVATION, viaSecond.scope());
        } finally {
            removeConfig(ConfigScope.ACTIVATION, null, key);
            if (secondActivationId != null) {                powerAuthClient.removeActivation(secondActivationId, "test");
            }
            //noinspection ResultOfMethodCallIgnored
            secondStatusFile.delete();
        }
    }

    @Test
    void blockedActivationRejectsActivationEndpointTest() throws Exception {
        // The activation endpoint relies on activation-scope ECIES, which requires the activation to be ACTIVE.
        // A BLOCKED activation must therefore fail to decrypt at the enrollment server. We use a dedicated
        // second activation so the primary test activation remains usable for the rest of the suite.
        final File statusFile = File.createTempFile("pa_status_blocked_", ".json");
        final JSONObject statusObject = new JSONObject();
        String secondActivationId = null;
        try {
            secondActivationId = initAndActivate(statusFile, statusObject);
            final EncryptStepModel secondEncryptModel = buildEncryptModelForActivation(statusObject);

            // Sanity check: the freshly-created activation can fetch configuration.
            secondEncryptModel.setUriString(config.getEnrollmentServiceUrl() + "/pa/v4/config/activation");
            secondEncryptModel.setScope("activation");
            secondEncryptModel.setData("{}".getBytes(StandardCharsets.UTF_8));
            final ObjectStepLogger sanityLogger = new ObjectStepLogger(System.out);
            new EncryptStep().execute(sanityLogger, secondEncryptModel.toMap());
            assertTrue(sanityLogger.getResult().success(),
                    "Sanity: the activation endpoint must succeed before the activation is blocked");

            // Block and re-attempt — the call must now fail.
            powerAuthClient.blockActivation(secondActivationId, "test-blocked", "test");
            final ObjectStepLogger blockedLogger = new ObjectStepLogger(System.out);
            new EncryptStep().execute(blockedLogger, secondEncryptModel.toMap());
            assertFalse(blockedLogger.getResult().success(),
                    "A blocked activation must not be able to fetch configuration via the activation endpoint");
        } finally {
            if (secondActivationId != null) {
                try { powerAuthClient.unblockActivation(secondActivationId, "test"); } catch (Exception ignored) {}
                powerAuthClient.removeActivation(secondActivationId, "test");
            }
            //noinspection ResultOfMethodCallIgnored
            statusFile.delete();
        }
    }

    @Test
    void perDeviceConfigRemovedWhenActivationRemovedTest() throws Exception {
        // Per spec confirmation: when an activation is removed, its per-device configuration items must
        // also be removed. Cross-checked via the management listing API (the SDK fetch endpoint is no
        // longer reachable once the activation is gone).
        final File statusFile = File.createTempFile("pa_status_perdevice_remove_", ".json");
        final JSONObject statusObject = new JSONObject();
        final String key = uniqueKey();
        String secondActivationId = null;
        boolean activationRemoved = false;
        try {
            secondActivationId = initAndActivate(statusFile, statusObject);
            createConfig(ConfigScope.ACTIVATION, secondActivationId, key, "per-device-secret");

            // Precondition: the per-device document contains exactly the new key.
            final GetConfigItemsResponse beforeRemoval = listManagementConfig(secondActivationId);
            assertTrue(beforeRemoval.getConfigs().stream().anyMatch(it -> key.equals(it.getKey())),
                    "Per-device item must be present before the activation is removed");

            powerAuthClient.removeActivation(secondActivationId, "test");
            activationRemoved = true;

            // Postcondition: the per-device document is empty (or at minimum does not contain the key).
            final GetConfigItemsResponse afterRemoval = listManagementConfig(secondActivationId);
            assertTrue(afterRemoval.getConfigs().stream().noneMatch(it -> key.equals(it.getKey())),
                    "Per-device configuration must be removed together with the activation");
        } finally {
            if (secondActivationId != null && !activationRemoved) {
                powerAuthClient.removeActivation(secondActivationId, "test");
            }
            //noinspection ResultOfMethodCallIgnored
            statusFile.delete();
        }
    }

    @Test
    void removeConfigIsIdempotentForMissingKeyTest() {
        // Removing a key that does not exist must be a no-op, not an error — both at APPLICATION scope and
        // at per-device ACTIVATION scope. This keeps tear-down and reconciliation logic simple for callers.
        final String missingKey = uniqueKey();
        assertDoesNotThrow(() -> removeConfig(ConfigScope.APPLICATION, null, missingKey),
                "Removing a missing APPLICATION-scope key must be idempotent");
        assertDoesNotThrow(() -> removeConfig(ConfigScope.ACTIVATION, null, missingKey),
                "Removing a missing app-wide ACTIVATION-scope key must be idempotent");
        assertDoesNotThrow(() -> removeConfig(ConfigScope.ACTIVATION, config.getActivationId(VERSION), missingKey),
                "Removing a missing per-device key must be idempotent");
    }

    @Test
    void createConfigValidatesRequestTest() {
        // The management API must reject malformed requests with PowerAuthClientException (server-side 400).
        // Each case covers a single invariant of CreateConfigItemRequest.
        final String key = uniqueKey();

        // Missing applicationId.
        final CreateConfigItemRequest missingAppId = new CreateConfigItemRequest();
        missingAppId.setScope(ConfigScope.APPLICATION);
        missingAppId.setKey(key);
        missingAppId.setValue("v");
        assertThrows(PowerAuthClientException.class, () -> powerAuthClient.createConfigItem(missingAppId),
                "createConfig must reject a request without applicationId");

        // Missing key.
        final CreateConfigItemRequest missingKey = new CreateConfigItemRequest();
        missingKey.setApplicationId(config.getApplicationId());
        missingKey.setScope(ConfigScope.APPLICATION);
        missingKey.setValue("v");
        assertThrows(PowerAuthClientException.class, () -> powerAuthClient.createConfigItem(missingKey),
                "createConfig must reject a request without a key");

        // Missing scope.
        final CreateConfigItemRequest missingScope = new CreateConfigItemRequest();
        missingScope.setApplicationId(config.getApplicationId());
        missingScope.setKey(key);
        missingScope.setValue("v");
        assertThrows(PowerAuthClientException.class, () -> powerAuthClient.createConfigItem(missingScope),
                "createConfig must reject a request without a scope");

        // Missing value.
        final CreateConfigItemRequest missingValue = new CreateConfigItemRequest();
        missingValue.setApplicationId(config.getApplicationId());
        missingValue.setScope(ConfigScope.APPLICATION);
        missingValue.setKey(key);
        assertThrows(PowerAuthClientException.class, () -> powerAuthClient.createConfigItem(missingValue),
                "createConfig must reject a request without a value");
    }

    @Test
    void createConfigRejectsActivationIdWithApplicationScopeTest() {
        // Per the request contract: when activationId is present, scope must be ACTIVATION (per-device write).
        // The opposite combination — activationId + scope=APPLICATION — is incoherent and must be rejected.
        final CreateConfigItemRequest mismatched = new CreateConfigItemRequest();
        mismatched.setApplicationId(config.getApplicationId());
        mismatched.setActivationId(config.getActivationId(VERSION));
        mismatched.setScope(ConfigScope.APPLICATION);
        mismatched.setKey(uniqueKey());
        mismatched.setValue("v");
        assertThrows(PowerAuthClientException.class, () -> powerAuthClient.createConfigItem(mismatched),
                "createConfig must reject activationId combined with APPLICATION scope");
    }

    @Test
    void managementListingMatchesEncryptedFetchTest() throws Exception {
        // The management listing API (V4 getConfig) must surface the same items that the SDK sees through
        // the E2EE fetch endpoint. This locks the agreement between the two API surfaces so that operators
        // never see a different picture than the device does.
        final String activationId = config.getActivationId(VERSION);
        final String keyAppOnly = uniqueKey();
        final String keyActWide = uniqueKey();
        final String keyPerDevice = uniqueKey();
        createConfig(ConfigScope.APPLICATION, null, keyAppOnly, "app-listing");
        createConfig(ConfigScope.ACTIVATION, null, keyActWide, "act-listing");
        createConfig(ConfigScope.ACTIVATION, activationId, keyPerDevice, "device-listing");
        try {
            // Management listing for application-level documents (no activationId) — both APPLICATION and
            // app-wide ACTIVATION entries must be present.
            final GetConfigItemsResponse appLevel = listManagementConfig(null);
            assertTrue(appLevel.getConfigs().stream().anyMatch(it -> keyAppOnly.equals(it.getKey())
                            && it.getScope() == ConfigScope.APPLICATION),
                    "Management listing must include the APPLICATION-scope item");
            assertTrue(appLevel.getConfigs().stream().anyMatch(it -> keyActWide.equals(it.getKey())
                            && it.getScope() == ConfigScope.ACTIVATION),
                    "Management listing must include the app-wide ACTIVATION-scope item");
            assertTrue(appLevel.getConfigs().stream().noneMatch(it -> keyPerDevice.equals(it.getKey())),
                    "Management listing without activationId must NOT include per-device items");

            // Management listing for the per-device document.
            final GetConfigItemsResponse perDevice = listManagementConfig(activationId);
            assertTrue(perDevice.getConfigs().stream().anyMatch(it -> keyPerDevice.equals(it.getKey())),
                    "Per-device management listing must include the per-device key");
            assertTrue(perDevice.getConfigs().stream().noneMatch(it -> keyAppOnly.equals(it.getKey())),
                    "Per-device management listing must NOT include application-level keys");
            assertTrue(perDevice.getConfigs().stream().noneMatch(it -> keyActWide.equals(it.getKey())),
                    "Per-device management listing must NOT include app-wide ACTIVATION keys");

            // Parity with the SDK view: keys present in the SDK activation response must also be present
            // somewhere in the management view (either app-level or per-device).
            final ConfigResponse sdkActivation = fetchConfig("activation");
            for (final String expectedKey : List.of(keyAppOnly, keyActWide, keyPerDevice)) {
                assertNotNull(findItem(sdkActivation, expectedKey),
                        "Key " + expectedKey + " must be visible to the SDK through the activation endpoint");
            }
        } finally {
            removeConfig(ConfigScope.APPLICATION, null, keyAppOnly);
            removeConfig(ConfigScope.ACTIVATION, null, keyActWide);
            removeConfig(ConfigScope.ACTIVATION, activationId, keyPerDevice);
        }
    }

    private GetConfigItemsResponse listManagementConfig(final String activationId) throws PowerAuthClientException {
        final GetConfigItemsRequest request = new GetConfigItemsRequest();
        request.setApplicationId(config.getApplicationId());
        request.setActivationId(activationId);
        return powerAuthClient.getConfigItems(request);
    }

    private ConfigResponse fetchConfig(final String scope) throws Exception {
        return fetchConfig(encryptModel, scope);
    }

    private ConfigResponse fetchConfig(final EncryptStepModel model, final String scope) throws Exception {
        model.setUriString(config.getEnrollmentServiceUrl() + "/pa/v4/config/" + scope);
        model.setScope(scope);
        model.setData("{}".getBytes(StandardCharsets.UTF_8));

        final ObjectStepLogger stepLogger = new ObjectStepLogger(System.out);
        new EncryptStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        return stepLogger.getItems().stream()
                .filter(isStepItemDecryptedResponse())
                .map(StepItem::object)
                .map(Object::toString)
                .map(it -> safeReadValue(it, ConfigResponse.class))
                .filter(Objects::nonNull)
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError("Decrypted data not found"));
    }

    /**
     * Creates a second activation (init → prepare → confirm → commit) using temporary state.
     *
     * @param statusFile   temporary file used to persist the activation status between steps.
     * @param statusObject in-memory JSON object that accumulates the activation state.
     * @return the activation ID of the newly committed activation.
     */
    private String initAndActivate(final File statusFile, final JSONObject statusObject) throws Exception {
        final InitActivationRequest initRequest = new InitActivationRequest();
        initRequest.setApplicationId(config.getApplicationId());
        initRequest.setUserId("TestUser_isolation_" + UUID.randomUUID());
        final InitActivationResponse initResponse = powerAuthClient.initActivation(initRequest);

        final PrepareActivationStepModel prepareModel = new PrepareActivationStepModel();
        prepareModel.setActivationCode(initResponse.getActivationCode());
        prepareModel.setActivationName("test-isolation");
        prepareModel.setApplicationKey(config.getApplicationKey());
        prepareModel.setApplicationSecret(config.getApplicationSecret());
        prepareModel.setMasterPublicKeyP256(config.getMasterPublicKeyP256());
        prepareModel.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
        prepareModel.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
        prepareModel.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        prepareModel.setHeaders(new HashMap<>());
        prepareModel.setPassword(config.getPassword());
        prepareModel.setStatusFileName(statusFile.getAbsolutePath());
        prepareModel.setResultStatusObject(statusObject);
        prepareModel.setUriString(config.getPowerAuthIntegrationUrl());
        prepareModel.setVersion(VERSION);
        prepareModel.setDeviceInfo("backend-tests");

        final ObjectStepLogger stepLoggerPrepare = new ObjectStepLogger(System.out);
        new PrepareActivationStep().execute(stepLoggerPrepare, prepareModel.toMap());
        assertTrue(stepLoggerPrepare.getResult().success(), "Prepare activation must succeed for the second activation");

        final ConfirmActivationStepModel confirmModel = new ConfirmActivationStepModel();
        confirmModel.setApplicationKey(config.getApplicationKey());
        confirmModel.setApplicationSecret(config.getApplicationSecret());
        confirmModel.setEnableBiometry(false);
        confirmModel.setPassword(config.getPassword());
        confirmModel.setVersion(VERSION);
        confirmModel.setStatusFileName(statusFile.getAbsolutePath());
        confirmModel.setResultStatusObject(statusObject);
        confirmModel.setUriString(config.getPowerAuthIntegrationUrl());

        final ObjectStepLogger stepLoggerConfirm = new ObjectStepLogger(System.out);
        new ConfirmActivationStep().execute(stepLoggerConfirm, confirmModel.toMap());
        assertTrue(stepLoggerConfirm.getResult().success(), "Confirm activation must succeed for the second activation");

        powerAuthClient.commitActivation(initResponse.getActivationId(), "test");
        return initResponse.getActivationId();
    }

    /**
     * Builds an {@link EncryptStepModel} configured for the activation whose state is held in {@code statusObject}.
     * The caller must have already completed the activate flow so that {@code statusObject} contains the
     * activation-derived cryptographic material needed for activation-scope ECIES.
     *
     * @param statusObject in-memory JSON object populated during activation preparation.
     * @return a ready-to-use model for activation-scope encrypt calls.
     */
    private EncryptStepModel buildEncryptModelForActivation(final JSONObject statusObject) {
        final EncryptStepModel model = new EncryptStepModel();
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKeyP384(config.getMasterPublicKeyP384());
        model.setMasterPublicKeyMlDsa65(config.getMasterPublicKeyMlDsa65());
        model.setHeaders(new HashMap<>());
        model.setResultStatusObject(statusObject);
        model.setBaseUriString(config.getPowerAuthIntegrationUrl());
        model.setSharedSecretAlgorithm(SharedSecretAlgorithm.EC_P384_ML_L3);
        model.setVersion(VERSION);
        return model;
    }

    private void createConfig(final ConfigScope scope, final String activationId, final String key, final Object value) throws Exception {
        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(config.getApplicationId());
        request.setActivationId(activationId);
        request.setScope(scope);
        request.setKey(key);
        request.setValue(value);
        powerAuthClient.createConfigItem(request);
    }

    private void removeConfig(final ConfigScope scope, final String activationId, final String key) throws Exception {
        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(config.getApplicationId());
        request.setActivationId(activationId);
        request.setScope(scope);
        request.setKey(key);
        powerAuthClient.removeConfigItem(request);
    }

    private static ConfigItem findItem(final ConfigResponse response, final String key) {
        return response.config().stream()
                .filter(it -> key.equals(it.key()))
                .findFirst()
                .orElse(null);
    }

    private static String uniqueKey() {
        return "test_config_" + UUID.randomUUID().toString().replace("-", "_");
    }

    private static Predicate<StepItem> isStepItemDecryptedResponse() {
        return stepItem -> "Decrypted Response".equals(stepItem.name());
    }

    private static <T> T safeReadValue(final String value, final Class<T> type) {
        try {
            return OBJECT_MAPPER.readValue(value, type);
        } catch (JacksonException e) {
            fail("Unable to read json", e);
            return null;
        }
    }

}

