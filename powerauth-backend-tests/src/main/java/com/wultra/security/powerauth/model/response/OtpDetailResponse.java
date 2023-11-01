package com.wultra.security.powerauth.model.response;

import lombok.Data;

/**
 * OTP detail response model class.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class OtpDetailResponse {

    private String processId;
    private String otpCode;

}
