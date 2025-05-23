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
package com.wultra.security.powerauth.test.shared.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.model.TemporaryKey;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.util.JsonUtil;
import com.wultra.security.powerauth.lib.cmd.util.MapUtil;
import com.wultra.security.powerauth.lib.cmd.util.RestClientFactory;
import com.wultra.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import com.wultra.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Utilities for fetching temporary keys from the server.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class TemporaryKeyFetchUtil {

    private TemporaryKeyFetchUtil() {
    }

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();

    /**
     * Fetch temporary key for encryption from the server.
     * @param version Protocol version.
     * @param scope Encryption scope.
     * @param config Test configuration.
     * @throws Exception Thrown in case temporary key fetch fails.
     */
    public static TemporaryKey fetchTemporaryKey(PowerAuthVersion version, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        if (version.useTemporaryKeys()) {
            return fetchTemporaryKeyImpl(version, scope, config);
        }
        return null;
    }

    private static TemporaryKey fetchTemporaryKeyImpl(PowerAuthVersion version, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        final String baseUri = config.getEnrollmentServiceUrl();
        final Map<String, String> headers = prepareHeaders();
        final String uri = baseUri + "/pa/v3/keystore/create";
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final String requestData = createJwtRequest(version, scope, challenge, config);
        final TemporaryKeyRequest jwtData = new TemporaryKeyRequest();
        jwtData.setJwt(requestData);
        final ObjectRequest<TemporaryKeyRequest> request = new ObjectRequest<>(jwtData);
        final RestClient restClient = RestClientFactory.getRestClient();
        final ObjectResponse<TemporaryKeyResponse> response = Objects.requireNonNull(restClient).postObject(uri, request, null, MapUtil.toMultiValueMap(headers), TemporaryKeyResponse.class);
        return handleTemporaryKeyResponse(version, response, scope, config);
    }

    private static Map<String, String> prepareHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

    private static String createJwtRequest(PowerAuthVersion version, EncryptorScope scope, String challenge, PowerAuthTestConfiguration config) throws Exception {
        final String applicationKey = config.getApplicationKey();
        final String activationId = scope == EncryptorScope.ACTIVATION_SCOPE ? config.getActivationId(version) : null;
        final Instant now = Instant.now();
        final JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .claim("applicationKey", applicationKey)
                .claim("activationId", activationId)
                .claim("challenge", challenge)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                .build();
        final byte[] secretKey = getSecretKey(version, scope, config);
        return signJwt(jwtClaims, secretKey);
    }

    private static byte[] getSecretKey(PowerAuthVersion version, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        final String appSecret = config.getApplicationSecret();
        if (scope == EncryptorScope.APPLICATION_SCOPE) {
            return Base64.getDecoder().decode(appSecret);
        } else if (scope == EncryptorScope.ACTIVATION_SCOPE) {
            final byte[] transportMasterKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "transportMasterKey"));
            final SecretKey transportMasterKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(transportMasterKeyBytes);
            final byte[] appSecretBytes = Base64.getDecoder().decode(appSecret);
            final SecretKey secretKeyBytes = KEY_GENERATOR.deriveSecretKeyHmac(transportMasterKey, appSecretBytes);
            return KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKeyBytes);
        }
        return null;
    }

    private static String signJwt(JWTClaimsSet jwtClaims, byte[] secretKey) throws Exception {
        final JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
        final byte[] payloadBytes = jwtClaims.toPayload().toBytes();
        final Base64URL encodedHeader = jwsHeader.toBase64URL();
        final Base64URL encodedPayload = Base64URL.encode(payloadBytes);
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] hash = new HMACHashUtilities().hash(secretKey, signingInput.getBytes(StandardCharsets.UTF_8));
        final Base64URL signature = Base64URL.encode(hash);
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    private static TemporaryKey handleTemporaryKeyResponse(PowerAuthVersion version, ObjectResponse<TemporaryKeyResponse> response, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        final String jwtResponse = response.getResponseObject().getJwt();
        final SignedJWT decodedJWT = SignedJWT.parse(jwtResponse);
        final PublicKey publicKey = switch (scope) {
            case ACTIVATION_SCOPE -> {
                final byte[] serverPublicKeyBytes = Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "serverPublicKey"));
                yield KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, serverPublicKeyBytes);
            }
            case APPLICATION_SCOPE -> config.getMasterPublicKeyP256();
        };

        if (!validateJwtSignature(decodedJWT, publicKey)) {
            return null;
        }
        final TemporaryKey temporaryKey = new TemporaryKey();
        temporaryKey.setId((String) decodedJWT.getJWTClaimsSet().getClaim("sub"));
        final String temporaryPublicKeyBase64 = (String) decodedJWT.getJWTClaimsSet().getClaim("publicKey");
        final byte[] temporaryPublicKeyBytes = Base64.getDecoder().decode(temporaryPublicKeyBase64);
        final PublicKey temporaryPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, temporaryPublicKeyBytes);
        temporaryKey.setPublicKey(temporaryPublicKey);
        return temporaryKey;
    }

    private static boolean validateJwtSignature(SignedJWT jwt, PublicKey publicKey) throws Exception {
        final Base64URL[] jwtParts = jwt.getParsedParts();
        final Base64URL encodedHeader = jwtParts[0];
        final Base64URL encodedPayload = jwtParts[1];
        final Base64URL encodedSignature = jwtParts[2];
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] signatureBytes = convertRawSignatureToDER(encodedSignature.decode());
        return SIGNATURE_UTILS.validateECDSASignature(signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes, publicKey);
    }

    private static byte[] convertRawSignatureToDER(byte[] rawSignature) throws Exception {
        if (rawSignature.length % 2 != 0) {
            throw new IllegalArgumentException("Invalid ECDSA signature format");
        }
        int len = rawSignature.length / 2;
        byte[] rBytes = new byte[len];
        byte[] sBytes = new byte[len];
        System.arraycopy(rawSignature, 0, rBytes, 0, len);
        System.arraycopy(rawSignature, len, sBytes, 0, len);
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DLSequence(v).getEncoded();
    }

}