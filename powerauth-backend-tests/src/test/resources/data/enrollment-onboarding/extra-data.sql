INSERT INTO es_onboarding_process_configuration (id, process_type, config) VALUES
    -- activationType IDENTITY, with OTPs
    (1, 'reactivation', '{"enabled":true,"activationType":"IDENTITY","otpForIdentification":true,"otpForIdentityVerification":true,"documents":{"totalRequiredDocumentsCount":2,"groups":[{"requiredDocumentsCount":1,"items":[{"type":"ID_CARD","sideCount":2}]},{"requiredDocumentsCount":1,"items":[{"type":"PASSPORT","sideCount":1},{"type":"DRIVING_LICENCE","sideCount":1}]}]}}'),

    -- activationType CODE, without OTPs, with temp activation, with approval
    (2, 'onboarding', '{"enabled":true,"activationType":"CODE","otpForIdentification":false,"otpForIdentityVerification":false,"useTemporaryActivation":true,"approvalEnabled":true,"verifyPresenceWithOtp":false,"documents":{"totalRequiredDocumentsCount":2,"groups":[{"requiredDocumentsCount":1,"items":[{"type":"ID_CARD","sideCount":2}]},{"requiredDocumentsCount":1,"items":[{"type":"PASSPORT","sideCount":1},{"type":"DRIVING_LICENCE","sideCount":1}]}]}}'),

    -- activationType CODE, without OTPs, without temp activation, without approval
    (3, 'onboardingSimple', '{"enabled":true,"activationType":"CODE","otpForIdentification":false,"otpForIdentityVerification":false,"verifyPresenceWithOtp":false,"documents":{"totalRequiredDocumentsCount":2,"groups":[{"requiredDocumentsCount":1,"items":[{"type":"ID_CARD","sideCount":2}]},{"requiredDocumentsCount":1,"items":[{"type":"PASSPORT","sideCount":1},{"type":"DRIVING_LICENCE","sideCount":1}]}]}}');
