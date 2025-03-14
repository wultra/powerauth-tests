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
package com.wultra.security.powerauth.test.v32;

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse;
import com.wultra.security.powerauth.configuration.PowerAuthOidcActivationConfigurationProperties;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.logging.ObjectStepLogger;
import com.wultra.security.powerauth.lib.cmd.steps.context.StepContext;
import com.wultra.security.powerauth.lib.cmd.steps.model.CreateActivationStepModel;
import com.wultra.security.powerauth.lib.cmd.steps.v3.CreateActivationStep;
import com.wultra.security.powerauth.rest.api.model.entity.ActivationType;
import com.wultra.security.powerauth.rest.api.model.request.ActivationLayer1Request;
import com.wultra.security.powerauth.rest.api.model.response.ActivationLayer2Response;
import com.wultra.security.powerauth.rest.api.spring.service.oidc.OidcApplicationConfiguration;
import com.wultra.security.powerauth.rest.api.spring.service.oidc.OidcApplicationConfigurationService;
import com.wultra.security.powerauth.rest.api.spring.service.oidc.OidcConfigurationQuery;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.EnabledIf;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test direct activation via OIDC.
 * <p>
 * Mind that {@code powerauth.test.activation.*} properties must be filled, otherwise the test is ignored.
 * Also a database entry must exist in the table {@code pa_application_config} with a config key {@code oauth2_providers} and appropriate config values.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableConfigurationProperties
@ComponentScan(basePackages = "com.wultra.security.powerauth")
@EnabledIf(expression = "#{T(org.springframework.util.StringUtils).hasText('${powerauth.test.activation.oidc.providerId}')}", loadContext = true)
class PowerAuthOidcActivationTest {

    private static final PowerAuthVersion VERSION = PowerAuthVersion.V3_2;

    private static File dataFile;

    @Autowired
    private PowerAuthTestConfiguration config;

    @Autowired
    private PowerAuthOidcActivationConfigurationProperties oidcConfigProperties;

    @Autowired
    private OidcApplicationConfigurationService oidcApplicationConfigurationService;

    @Autowired
    private PowerAuthClient powerAuthClient;

    @LocalServerPort
    private int port;

    private CreateActivationStepModel model;
    private ObjectStepLogger stepLogger;
    private OidcApplicationConfiguration oidcConfig;

    @BeforeAll
    static void setUpBeforeClass() throws IOException {
        dataFile = File.createTempFile("data", ".json");
        FileWriter fw = new FileWriter(dataFile);
        fw.write("All your base are belong to us!");
        fw.close();
    }

    @AfterAll
    static void tearDownAfterClass() {
        assertTrue(dataFile.delete());
    }

    @BeforeEach
    void setUp() throws Exception {
        final File tempStatusFile = File.createTempFile("pa_status_" + VERSION, ".json");

        model = new CreateActivationStepModel();
        model.setActivationName("test v" + VERSION);
        model.setApplicationKey(config.getApplicationKey());
        model.setApplicationSecret(config.getApplicationSecret());
        model.setMasterPublicKey(config.getMasterPublicKey());
        model.setHeaders(new HashMap<>());
        model.setPassword(config.getPassword());
        model.setStatusFileName(tempStatusFile.getAbsolutePath());
        model.setResultStatusObject(config.getResultStatusObject(VERSION));
        model.setUriString("http://localhost:" + port);
        model.setVersion(VERSION);
        model.setDeviceInfo("backend-tests");

        stepLogger = new ObjectStepLogger(System.out);

        oidcConfig = oidcApplicationConfigurationService.fetchOidcApplicationConfiguration(OidcConfigurationQuery.builder()
                .applicationKey(config.getApplicationKey())
                .providerId(oidcConfigProperties.getProviderId())
                .build());
    }

    @Test
    void testOidcActivation() throws Exception {
        final String nonce = generateRandomString();

        final WebClient webClient = createWebClient();
        final UriComponents authorizeUriComponents = authorize(webClient, nonce);
        final String code = login(webClient, authorizeUriComponents);
        assertNotNull(code);

        final Map<String, String> identityAttributes = Map.of(
                "method", "oidc",
                "providerId", oidcConfig.getProviderId(),
                "code", code,
                "nonce", nonce
        );
        createActivation(identityAttributes);
    }

    @Test
    void testOidcPkceActivation() throws Exception {
        final String nonce = generateRandomString();
        final String codeVerifier = generateRandomString();
        final String codeChallenge = convertToCodeChallenge(codeVerifier);

        final WebClient webClient = createWebClient();
        final UriComponents authorizeUriComponents = authorizeWithPkce(webClient, nonce, codeChallenge);
        final String code = login(webClient, authorizeUriComponents);
        assertNotNull(code);

        final Map<String, String> identityAttributes = Map.of(
                "method", "oidc",
                "providerId", oidcConfig.getProviderId(),
                "code", code,
                "nonce", nonce,
                "codeVerifier", codeVerifier
        );
        createActivation(identityAttributes);
    }

    private static String convertToCodeChallenge(final String codeVerifier) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private UriComponents authorize(final WebClient webClient, final String nonce) {
        final Map<String, String> uriVariables = Map.of(
                "clientId", oidcConfig.getClientId(),
                "redirectUri", oidcConfig.getRedirectUri(),
                "state", generateRandomString(),
                "nonce", nonce,
                "scope", oidcConfig.getScopes()
        );
        final String authorizationUrl = oidcConfig.getIssuerUri() + "/authorize?client_id={clientId}&redirect_uri={redirectUri}&scope={scope}&state={state}&nonce={nonce}&response_type=code";
        final WebClient.ResponseSpec responseSpec = webClient.get().uri(authorizationUrl, uriVariables).retrieve();
        return UriComponentsBuilder.fromUri(fetchRedirectUri(responseSpec)).build();
    }

    private UriComponents authorizeWithPkce(final WebClient webClient, final String nonce, final String codeChallenge) {
        final Map<String, String> uriVariables = Map.of(
                "clientId", oidcConfig.getClientId(),
                "redirectUri", oidcConfig.getRedirectUri(),
                "state", generateRandomString(),
                "nonce", nonce,
                "scope", oidcConfig.getScopes(),
                "code_challenge", codeChallenge,
                "code_challenge_method", "S256"
        );
        final String authorizationUrl = oidcConfig.getIssuerUri() + "/authorize?client_id={clientId}&redirect_uri={redirectUri}&scope={scope}&state={state}&nonce={nonce}&response_type=code&code_challenge={code_challenge}&code_challenge_method={code_challenge_method}";
        final WebClient.ResponseSpec responseSpec = webClient.get().uri(authorizationUrl, uriVariables).retrieve();
        return UriComponentsBuilder.fromUri(fetchRedirectUri(responseSpec)).build();
    }

    private String login(final WebClient webClient, final UriComponents authorizeUriComponents) {
        final String authorizeState = authorizeUriComponents.getQueryParams().getFirst("state");
        assertNotNull(authorizeState);

        final MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", oidcConfigProperties.getUsername());
        requestBody.add("password", oidcConfigProperties.getPassword());
        requestBody.add("state", authorizeState);

        final String loginUrl = oidcConfig.getIssuerUri() + authorizeUriComponents.getPath();
        final WebClient.ResponseSpec responseSpec = webClient
                .post()
                .uri(loginUrl)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters.fromFormData(requestBody))
                .retrieve();
        final URI redirectUri = fetchRedirectUri(responseSpec);
        return resumeLogin(webClient, oidcConfig.getIssuerUri() + redirectUri);
    }

    private String resumeLogin(final WebClient webClient, final String uri) {
        final WebClient.ResponseSpec responseSpec = webClient.get().uri(uri).retrieve();
        final URI redirectUri = fetchRedirectUri(responseSpec);
        final UriComponents uriComponents = UriComponentsBuilder.fromUri(redirectUri).build();
        return uriComponents.getQueryParams().getFirst("code");
    }

    private URI fetchRedirectUri(final WebClient.ResponseSpec responseSpec) {
        final ResponseEntity<Void> bodilessEntity = responseSpec.toBodilessEntity().block();
        assertNotNull(bodilessEntity);
        final HttpStatusCode statusCode = bodilessEntity.getStatusCode();
        assertTrue(statusCode.is3xxRedirection(), "Status Code: " + statusCode);
        final URI location = bodilessEntity.getHeaders().getLocation();
        assertNotNull(location);
        return location;
    }

    private static WebClient createWebClient() {
        final List<String> cookies = new ArrayList<>();

        final ExchangeFilterFunction cookieFilter = ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
            if (!cookies.isEmpty()) {
                clientRequest = ClientRequest.from(clientRequest)
                        .header(HttpHeaders.COOKIE, String.join("; ", cookies))
                        .build();
            }
            return Mono.just(clientRequest);
        }).andThen(ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
            cookies.clear();
            cookies.addAll(Objects.requireNonNull(clientResponse.headers().asHttpHeaders().get(HttpHeaders.SET_COOKIE)));
            return Mono.just(clientResponse);
        }));

        return WebClient.builder()
                .filter(cookieFilter)
                .build();
    }

    private static String generateRandomString() {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private void createActivation(final Map<String, String> identityAttributes) throws Exception {
        model.setIdentityAttributes(identityAttributes);

        new CreateOidcActivationStep().execute(stepLogger, model.toMap());
        assertTrue(stepLogger.getResult().success());
        assertEquals(200, stepLogger.getResponse().statusCode());

        final ActivationLayer2Response layer2Response = fetchLayer2Response(stepLogger);
        final String activationId = layer2Response.getActivationId();

        assertNotNull(activationId);
        assertNotNull(layer2Response.getCtrData());
        assertNotNull(layer2Response.getServerPublicKey());

        // Verify activation status - activation was automatically committed
        final GetActivationStatusResponse statusResponseActive = powerAuthClient.getActivationStatus(activationId);
        assertEquals(ActivationStatus.ACTIVE, statusResponseActive.getActivationStatus());
        assertEquals(oidcConfigProperties.getSub(), statusResponseActive.getUserId());

        powerAuthClient.removeActivation(activationId, "test");
    }

    private static ActivationLayer2Response fetchLayer2Response(final ObjectStepLogger stepLogger) {
        return stepLogger.getItems().stream()
                .filter(item -> "Decrypted Layer 2 Response".equals(item.name()))
                .map(item -> (ActivationLayer2Response) item.object())
                .findAny()
                .orElseThrow(() -> AssertionFailureBuilder.assertionFailure().message("Response was not successfully decrypted").build());
    }

    static class CreateOidcActivationStep extends CreateActivationStep{
        @Override
        protected ActivationLayer1Request prepareLayer1Request(final StepContext<CreateActivationStepModel, EciesEncryptedResponse> stepContext, final EciesEncryptedRequest encryptedRequestL2) {
            final ActivationLayer1Request activationLayer1Request = super.prepareLayer1Request(stepContext, encryptedRequestL2);
            activationLayer1Request.setType(ActivationType.DIRECT);
            return activationLayer1Request;
        }
    }
}
