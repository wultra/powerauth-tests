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

package com.wultra.security.powerauth.fido2.service;

import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.fido2.AssertionChallengeRequest;
import com.wultra.security.powerauth.client.model.request.fido2.AssertionVerificationRequest;
import com.wultra.security.powerauth.client.model.response.fido2.AssertionChallengeResponse;
import com.wultra.security.powerauth.client.model.response.fido2.AssertionVerificationResponse;
import com.wultra.security.powerauth.fido2.configuration.WebAuthnConfiguration;
import com.wultra.security.powerauth.fido2.controller.request.AssertionOptionsRequest;
import com.wultra.security.powerauth.fido2.controller.request.VerifyAssertionRequest;
import com.wultra.security.powerauth.fido2.controller.response.AssertionOptionsResponse;
import com.wultra.security.powerauth.fido2.controller.response.CredentialDescriptor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Service for WebAuthn authentication tasks.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class AssertionService {

    private static final String OPERATION_DATA_EXTENSION_KEY = "txAuthSimple";
    private static final String HMAC_SECRET_EXTENSION_KEY = "hmacGetSecret";
    private static final List<String> OPERATION_DATA_FIELDS_PRIORITY = List.of("I", "Q", "A", "R", "D", "N");

    private final PowerAuthFido2Client fido2Client;
    private final Fido2SharedService fido2SharedService;
    private final WebAuthnConfiguration webAuthNConfig;

    /**
     * Build public key assertion options.
     * @param request Request form with user input.
     * @return Public key assertion options.
     * @throws PowerAuthClientException in case of PowerAuth server communication error.
     */
    public AssertionOptionsResponse assertionOptions(final AssertionOptionsRequest request) throws PowerAuthClientException {
        final String userId = request.username();
        final String applicationId = request.applicationId();

        logger.info("Building assertion options for userId={}, applicationId={}", userId, applicationId);

        final List<CredentialDescriptor> existingCredentials = fido2SharedService.fetchExistingCredentials(userId, applicationId);
        if (existingCredentials.isEmpty() && StringUtils.hasText(userId))  {
            logger.info("User {} is not yet registered.", userId);
            throw new IllegalStateException("Not registered yet.");
        }

        final AssertionChallengeResponse challengeResponse = fetchChallenge(userId, applicationId, request.templateName(), request.operationParameters());
        final String challenge = challengeResponse.getChallenge();
        final String operationData = extractOperationData(challenge);
        final String shrunkOperationData = shrinkToFitByteArray(operationData);

        return AssertionOptionsResponse.builder()
                .challenge(challenge)
                .rpId(webAuthNConfig.getRpId())
                .timeout(webAuthNConfig.getTimeout().toMillis())
                .allowCredentials(existingCredentials)
                .extensions(Map.of(
                        OPERATION_DATA_EXTENSION_KEY, operationData,
                        HMAC_SECRET_EXTENSION_KEY, convertToExtension(shrunkOperationData))
                ).build();
    }

    /**
     * Verify credential at PowerAuth server.
     * @param credential Received public key credential.
     * @return PowerAuth authentication response.
     * @throws PowerAuthClientException in case of PowerAuth server communication error.
     */
    public AssertionVerificationResponse authenticate(final VerifyAssertionRequest credential) throws PowerAuthClientException {
        final AssertionVerificationRequest request = new AssertionVerificationRequest();
        request.setCredentialId(credential.id());
        request.setType(credential.type().getValue());
        request.setAuthenticatorAttachment(credential.authenticatorAttachment().getValue());
        request.setResponse(credential.response());
        request.setApplicationId(credential.applicationId());
        request.setExpectedChallenge(credential.expectedChallenge());
        request.setRelyingPartyId(webAuthNConfig.getRpId());
        request.setAllowedOrigins(webAuthNConfig.getAllowedOrigins());
        request.setRequiresUserVerification(credential.userVerificationRequired());

        final AssertionVerificationResponse response = fido2Client.authenticate(request);
        logger.debug("Credential assertion response of userId={}: {}", response.getUserId(), response);
        logger.info("Activation ID {} of userId={}: valid={}", response.getActivationId(), response.getUserId(), response.isAssertionValid());

        return response;
    }

    private AssertionChallengeResponse fetchChallenge(final String userId, final String applicationId, final String templateName, final Map<String, String> operationParameters) throws PowerAuthClientException {
        logger.info("Getting registration challenge for userId={}, applicationId={}, template={}, parameters={}", userId, applicationId, templateName, operationParameters);
        final AssertionChallengeRequest request = new AssertionChallengeRequest();
        request.setApplicationIds(List.of(applicationId));
        request.setTemplateName(templateName);
        if (operationParameters != null) {
            request.setParameters(operationParameters);
        }
        final AssertionChallengeResponse response = fido2Client.requestAssertionChallenge(request);
        logger.debug("Assertion challenge response for userId={}: {}", userId, response);
        return response;
    }

    private static String extractOperationData(final String challenge) {
        final String[] split = challenge.split("&", 2);
        if (split.length != 2) {
            throw new IllegalStateException("Invalid challenge format.");
        }
        return split[1];
    }

    /**
     * Function takes operation data in PowerAuth format and shrinks them, if necessary, to fit 64 bytes.
     * If the passed operation data are longer than 64 bytes, they are parsed and rebuild with only subset
     * of fields. The building process tries to greedy append all fields sorted by priority, until the array is full.
     * @param operationData Operation data to shrink.
     * @return Shrunk operation data.
     */
    private static String shrinkToFitByteArray(final String operationData) {
        if (fitsIntoByteArray(operationData)) {
            logger.debug("Operation data fits into array as is.");
            return operationData;
        }

        final Map<String, String> operationDataFields = parseOperationData(operationData);
        if (operationDataFields.isEmpty()) {
            throw new IllegalStateException("Operation data are present in unexpected format.");
        }
        String cropped = operationDataFields.get("header");

        for (final String fieldKey : OPERATION_DATA_FIELDS_PRIORITY) {
            cropped = appendIfFitsByteArray(cropped, operationDataFields, fieldKey);
        }

        logger.debug("Operation data were shrunk to {}", cropped);
        return cropped;
    }

    private static Map<String, String> parseOperationData(final String operationData) {
        final String[] fields = operationData.split("\\*");
        if (fields.length < 1) {
            return Collections.emptyMap();
        }

        final Map<String, String> fieldMap = Arrays.stream(fields)
                .skip(1)
                .filter(StringUtils::hasText)
                .collect(Collectors.toMap(field -> field.substring(0, 1), Function.identity()));
        fieldMap.put("header", fields[0]);
        return fieldMap;
    }

    private static String appendIfFitsByteArray(String croppedData, final Map<String, String> fields, final String fieldKey) {
        if (fields.containsKey(fieldKey) && fitsIntoByteArray(croppedData + "*" + fields.get(fieldKey))) {
            croppedData += "*" + fields.get(fieldKey);
        }
        return croppedData;
    }

    private static boolean fitsIntoByteArray(final String operationData) {
        return operationData.getBytes().length <= 64;
    }

    private static HMACGetSecretInput convertToExtension(final String operationData) {
        if (!fitsIntoByteArray(operationData)) {
            throw new IllegalStateException("Operation data are too long.");
        }

        final byte[] paddedBytes = new byte[64];
        Arrays.fill(paddedBytes, (byte) 0x2A);
        final byte[] operationDataBytes = operationData.getBytes();
        System.arraycopy(operationDataBytes, 0, paddedBytes, 0, operationDataBytes.length);

        final byte[] seed1 = Arrays.copyOfRange(paddedBytes, 0, 32);
        final byte[] seed2 = Arrays.copyOfRange(paddedBytes, 32, 64);
        return new HMACGetSecretInput(Base64.getEncoder().encodeToString(seed1), Base64.getEncoder().encodeToString(seed2));
    }

    public record HMACGetSecretInput(String seed1, String seed2) {}

}
