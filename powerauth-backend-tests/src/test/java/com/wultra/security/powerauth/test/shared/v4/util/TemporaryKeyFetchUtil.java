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
package com.wultra.security.powerauth.test.shared.v4.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import com.wultra.security.powerauth.crypto.client.v4.keyfactory.PowerAuthClientKeyFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.HMACHashUtilities;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SignatureUtils;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsaKeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.lib.cmd.consts.PowerAuthVersion;
import com.wultra.security.powerauth.lib.cmd.util.JsonUtil;
import com.wultra.security.powerauth.lib.cmd.util.MapUtil;
import com.wultra.security.powerauth.lib.cmd.util.RestClientFactory;
import com.wultra.security.powerauth.lib.cmd.util.SharedSecretUtil;
import com.wultra.security.powerauth.model.v4.TemporaryKey;
import com.wultra.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import com.wultra.security.powerauth.rest.api.model.request.v4.SharedSecretRequest;
import com.wultra.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import com.wultra.security.powerauth.rest.api.model.response.v4.SharedSecretResponse;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Utilities for fetching temporary keys from the server (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class TemporaryKeyFetchUtil {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR_EC = new KeyConvertor();
    private static final PqcDsaKeyConvertor KEY_CONVERTOR_PQC_DSA = new MlDsaKeyConvertor();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final PowerAuthClientKeyFactory CLIENT_KEY_FACTORY = new PowerAuthClientKeyFactory();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final PqcDsa PQC_DSA;

    private TemporaryKeyFetchUtil()  {
    }

    static {
        try {
            PQC_DSA = new MlDsa(MLDSAParameterSpec.ml_dsa_65);
        } catch (GenericCryptoException e) {
            throw new RuntimeException(e);
        }
    }

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
        final String uri = baseUri + "/pa/v4/keystore/create";
        final byte[] challengeBytes = KEY_GENERATOR.generateRandomBytes(18);
        final String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        final JwtWithClientContext requestData = createJwtRequest(version, scope, challenge, config);
        final TemporaryKeyRequest jwtData = new TemporaryKeyRequest();
        jwtData.setJwt(requestData.jwt);
        final ObjectRequest<TemporaryKeyRequest> request = new ObjectRequest<>(jwtData);
        final RestClient restClient = RestClientFactory.getRestClient();
        final ObjectResponse<TemporaryKeyResponse> response = Objects.requireNonNull(restClient).postObject(uri, request, null, MapUtil.toMultiValueMap(headers), TemporaryKeyResponse.class);
        return handleResponse(version, response, scope, config, requestData.ctx);
    }

    private static Map<String, String> prepareHeaders() {
        final Map<String, String> headers = new HashMap<>();
        headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        return headers;
    }

    private static JwtWithClientContext createJwtRequest(PowerAuthVersion version, EncryptorScope scope, String challenge, PowerAuthTestConfiguration config) throws Exception {
        final String applicationKey = config.getApplicationKey();
        final String activationId = scope == EncryptorScope.ACTIVATION_SCOPE ? config.getActivationId(version) : null;
        final Instant now = Instant.now();
        final AtomicReference<SharedSecretClientContext> ctxRef = new AtomicReference<>();
        final SharedSecretRequest sharedSecretRequest = SharedSecretUtil.buildSharedSecretRequest(
                SharedSecretAlgorithm.EC_P384_ML_L3,
                ctxRef::set
        );
        final JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .claim("applicationKey", applicationKey)
                .claim("activationId", activationId)
                .claim("challenge", challenge)
                .claim("sharedSecretRequest", sharedSecretRequest)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                .build();
        final byte[] secretKey = getSecretKey(version, scope, config);
        final String signedJwt = signJwt(jwtClaims, secretKey);
        return new JwtWithClientContext(signedJwt, ctxRef.get());
    }

    private static byte[] getSecretKey(PowerAuthVersion version, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        final String appSecret = config.getApplicationSecret();
        return switch (scope) {
            case APPLICATION_SCOPE -> {
                final SecretKey sourceKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(appSecret.getBytes(StandardCharsets.UTF_8));
                final SecretKey secretKey = CLIENT_KEY_FACTORY.generateKeyMacGetAppTempKey(sourceKey);
                yield KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(secretKey);
            }
            case ACTIVATION_SCOPE -> {
                final String tempKeyActSignBase64 = JsonUtil.stringValue(config.getResultStatusObject(version), "temporaryKeyActSignRequestKey");
                final byte[] tempKeyActSignBytes = Base64.getDecoder().decode(tempKeyActSignBase64);
                final SecretKey secretKey = KEY_CONVERTOR_EC.convertBytesToSharedSecretKey(tempKeyActSignBytes);
                yield KEY_CONVERTOR_EC.convertSharedSecretKeyToBytes(secretKey);
            }
        };
    }

    private static String signJwt(JWTClaimsSet jwtClaims, byte[] secretKey) throws Exception {
        final JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS384);
        final byte[] payloadBytes = jwtClaims.toPayload().toBytes();
        final Base64URL encodedHeader = jwsHeader.toBase64URL();
        final Base64URL encodedPayload = Base64URL.encode(payloadBytes);
        final String signingInput = encodedHeader + "." + encodedPayload;
        final byte[] hash = new HMACHashUtilities().hash384(secretKey, signingInput.getBytes(StandardCharsets.UTF_8));
        final Base64URL signature = Base64URL.encode(hash);
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    private static TemporaryKey handleResponse(PowerAuthVersion version, ObjectResponse<TemporaryKeyResponse> response, EncryptorScope scope,
            PowerAuthTestConfiguration config, SharedSecretClientContext ctx) throws Exception {
        final String jwt = response.getResponseObject().getJwt();
        final JWSObjectJSON json = JWSObjectJSON.parse(jwt);
        final Map<String, JwtSignedData> sigs = extract(json);
        validateHybridSignatures(version, sigs, scope, config);
        final JWTClaimsSet claims = JWTClaimsSet.parse(json.getPayload().toJSONObject());

        final TemporaryKey temporaryKey = new TemporaryKey();
        temporaryKey.setId((String) claims.getClaim("sub"));

        final SharedSecretResponse sharedSecretResponse = OBJECT_MAPPER.convertValue(claims.getClaim("sharedSecretResponse"), SharedSecretResponse.class);
        temporaryKey.setSharedSecret(SharedSecretUtil.deriveSharedSecret(sharedSecretResponse, ctx, SharedSecretAlgorithm.EC_P384_ML_L3));
        return temporaryKey;
    }

    private static void validateHybridSignatures(PowerAuthVersion version, Map<String, JwtSignedData> sigs, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        final PublicKey ecKey = resolveEcKey(version, scope, config);
        final JwtSignedData ecSig = sigs.get("ES384");
        if (ecSig == null || !validateEcSignature(ecSig, ecKey)) {
            throw new IllegalStateException("Invalid EC signature");
        }
        final PublicKey mldsaKey = resolveMldsaKey(version, scope, config);
        final JwtSignedData mldsaSig = sigs.get("ML-DSA-65");
        if (mldsaSig == null || !validateMldsaSignature(mldsaSig, mldsaKey)) {
            throw new IllegalStateException("Invalid MLDSA signature");
        }
    }

    private static PublicKey resolveEcKey(PowerAuthVersion version, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        return scope == EncryptorScope.APPLICATION_SCOPE ? config.getMasterPublicKeyP384() : KEY_CONVERTOR_EC.convertBytesToPublicKey(
                EcCurve.P384, Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "ecServerPublicKey"))
        );
    }

    private static PublicKey resolveMldsaKey(PowerAuthVersion version, EncryptorScope scope, PowerAuthTestConfiguration config) throws Exception {
        return scope == EncryptorScope.APPLICATION_SCOPE ? config.getMasterPublicKeyMlDsa65() : KEY_CONVERTOR_PQC_DSA.convertBytesToPublicKey(
                Base64.getDecoder().decode(JsonUtil.stringValue(config.getResultStatusObject(version), "pqcServerPublicKey"))
        );
    }

    private static boolean validateEcSignature(JwtSignedData sig, PublicKey key) throws Exception {
        byte[] der = convertRawSignatureToDER(Base64URL.from(sig.signature).decode());
        return SIGNATURE_UTILS.validateECDSASignature(EcCurve.P384, sig.input.getBytes(StandardCharsets.UTF_8), der, key);
    }

    private static boolean validateMldsaSignature(JwtSignedData sig, PublicKey key) throws Exception {
        return PQC_DSA.verify(key, sig.input.getBytes(StandardCharsets.UTF_8), Base64URL.from(sig.signature).decode());
    }

    private static Map<String, JwtSignedData> extract(JWSObjectJSON json) {
        return json.getSignatures().stream().collect(Collectors.toMap(
                s -> s.getHeader().getAlgorithm().getName(),
                s -> new JwtSignedData(
                        s.getSignature().toString(),
                        s.getHeader().toBase64URL() + "." + json.getPayload().toBase64URL()
                )
        ));
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

    private record JwtWithClientContext(String jwt, SharedSecretClientContext ctx) {}

    private record JwtSignedData(String signature, String input) {}

}