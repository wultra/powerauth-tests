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
package com.wultra.security.powerauth.test.v31;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.OperationApproveRequest;
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationDetailRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import com.wultra.security.powerauth.configuration.PowerAuthTestConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;

import static com.wultra.security.powerauth.client.model.enumeration.UserActionResult.APPROVAL_FAILED;
import static com.wultra.security.powerauth.client.model.enumeration.UserActionResult.APPROVED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test of PowerAuth operation endpoints.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = PowerAuthTestConfiguration.class)
@EnableConfigurationProperties
class PowerAuthOperationTest {

    @Autowired
    private PowerAuthClient powerAuthClient;

    @Autowired
    private PowerAuthTestConfiguration config;

    @Test
    void testOperationApprove() throws Exception {
        final OperationDetailResponse operation = createOperation();

        final OperationApproveRequest approveRequest = createOperationApproveRequest(operation.getId());

        final OperationUserActionResponse result = powerAuthClient.operationApprove(approveRequest);

        assertEquals(APPROVED, result.getResult());
    }

    @Test
    void testOperationApproveWithValidProximityOtp() throws Exception {
        final OperationDetailResponse operation = createOperation(true);

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());

        final String totp = powerAuthClient.operationDetail(detailRequest).getTotp();
        assertNotNull(totp);

        final OperationApproveRequest approveRequest = createOperationApproveRequest(operation.getId());
        approveRequest.getAdditionalData().put("proximity_otp", totp);

        final OperationUserActionResponse result = powerAuthClient.operationApprove(approveRequest);

        assertEquals(APPROVED, result.getResult());
    }

    @Test
    void testOperationApproveWithInvalidProximityOtp() throws Exception {
        final OperationDetailResponse operation = createOperation(true);

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());

        final String totp = powerAuthClient.operationDetail(detailRequest).getTotp();
        assertNotNull(totp);

        final OperationApproveRequest approveRequest = createOperationApproveRequest(operation.getId());
        approveRequest.getAdditionalData().put("proximity_otp", "1111"); // invalid otp on purpose, it is too short

        final OperationUserActionResponse result = powerAuthClient.operationApprove(approveRequest);

        assertEquals(APPROVAL_FAILED, result.getResult());
    }

    private OperationApproveRequest createOperationApproveRequest(final String operationId) {
        final OperationApproveRequest approveRequest = new OperationApproveRequest();
        approveRequest.setOperationId(operationId);
        approveRequest.setUserId(config.getUserV31());
        approveRequest.setApplicationId(config.getApplicationId());
        approveRequest.setData("A2");
        approveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        return approveRequest;
    }

    private OperationDetailResponse createOperation() throws PowerAuthClientException {
        return createOperation(null);
    }

    private OperationDetailResponse createOperation(final Boolean proximityCheckEnabled) throws PowerAuthClientException {
        final OperationCreateRequest createRequest = new OperationCreateRequest();
        createRequest.setApplications(List.of(config.getApplicationName()));
        createRequest.setUserId(config.getUserV31());
        createRequest.setTemplateName(config.getLoginOperationTemplateName());
        createRequest.setProximityCheckEnabled(proximityCheckEnabled);

        return powerAuthClient.createOperation(createRequest);
    }
}
