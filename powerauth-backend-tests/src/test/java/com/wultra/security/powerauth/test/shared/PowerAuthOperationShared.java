/*
 * PowerAuth test and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
package com.wultra.security.powerauth.test.shared;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.OperationApproveRequest;
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationDetailRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;

import java.util.List;

import static com.wultra.security.powerauth.client.model.enumeration.UserActionResult.APPROVAL_FAILED;
import static com.wultra.security.powerauth.client.model.enumeration.UserActionResult.APPROVED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * PowerAuth operations test shared logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthOperationShared {

    public static void testOperationApprove(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final String version) throws Exception {
        final OperationDetailResponse operation = createOperation(powerAuthClient, config, version);

        final OperationApproveRequest approveRequest = createOperationApproveRequest(config, operation.getId(), version);

        final OperationUserActionResponse result = powerAuthClient.operationApprove(approveRequest);

        assertEquals(APPROVED, result.getResult());
    }

    public static void testOperationApproveWithValidProximityOtp(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final String version) throws Exception {
        final OperationDetailResponse operation = createOperation(powerAuthClient, config, true, version);

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());

        final String totp = powerAuthClient.operationDetail(detailRequest).getProximityOtp();
        assertNotNull(totp);

        final OperationApproveRequest approveRequest = createOperationApproveRequest(config, operation.getId(), version);
        approveRequest.getAdditionalData().put("proximity_otp", totp);

        final OperationUserActionResponse result = powerAuthClient.operationApprove(approveRequest);

        assertEquals(APPROVED, result.getResult());
    }

    public static void testOperationApproveWithInvalidProximityOtp(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final String version) throws Exception {
        final OperationDetailResponse operation = createOperation(powerAuthClient, config, true, version);

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());

        final String totp = powerAuthClient.operationDetail(detailRequest).getProximityOtp();
        assertNotNull(totp);

        final OperationApproveRequest approveRequest = createOperationApproveRequest(config, operation.getId(), version);
        approveRequest.getAdditionalData().put("proximity_otp", "1111"); // invalid otp on purpose, it is too short

        final OperationUserActionResponse result = powerAuthClient.operationApprove(approveRequest);

        assertEquals(APPROVAL_FAILED, result.getResult());
    }

    private static OperationApproveRequest createOperationApproveRequest(final PowerAuthTestConfiguration config, final String operationId, final String version) {
        final OperationApproveRequest approveRequest = new OperationApproveRequest();
        approveRequest.setOperationId(operationId);
        approveRequest.setUserId(config.getUser(version));
        approveRequest.setApplicationId(config.getApplicationId());
        approveRequest.setData("A2");
        approveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        return approveRequest;
    }

    private static OperationDetailResponse createOperation(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, String version) throws PowerAuthClientException {
        return createOperation(powerAuthClient, config, null, version);
    }

    private static OperationDetailResponse createOperation(final PowerAuthClient powerAuthClient, final PowerAuthTestConfiguration config, final Boolean proximityCheckEnabled, final String version) throws PowerAuthClientException {
        final OperationCreateRequest createRequest = new OperationCreateRequest();
        createRequest.setApplications(List.of(config.getApplicationName()));
        createRequest.setUserId(config.getUser(version));
        createRequest.setTemplateName(config.getLoginOperationTemplateName());
        createRequest.setProximityCheckEnabled(proximityCheckEnabled);

        return powerAuthClient.createOperation(createRequest);
    }
}
