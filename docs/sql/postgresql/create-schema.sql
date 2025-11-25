CREATE TABLE IF NOT EXISTS pa_test_config
(
    application_id     VARCHAR(255) NOT NULL PRIMARY KEY, -- Application identifier
    application_name   VARCHAR(255) NOT NULL,             -- Application name
    application_key    VARCHAR(255) NOT NULL,             -- Application key
    application_secret VARCHAR(255) NOT NULL,             -- Application secret
    master_public_key  VARCHAR(255)                       -- Master public key in Base64 format (v3)
    mobile_sdk_config  TEXT                               -- Mobile SDK configuration in Base64 format (v4)
);

CREATE TABLE IF NOT EXISTS pa_test_status
(
    activation_id                      VARCHAR(255) NOT NULL PRIMARY KEY, -- Activation identifier
    server_public_key                  VARCHAR(255),                      -- Server public key (EC) in Base64 format
    counter                            INTEGER      NOT NULL,             -- Numeric counter
    ctr_data                           VARCHAR(255) NOT NULL,             -- Hashed counter data
    encrypted_device_private_key       VARCHAR(255),                      -- Encrypted device private key in Base64 format
    signature_biometry_key             VARCHAR(255),                      -- Signature biometry key in Base64 format
    signature_knowledge_key_encrypted  VARCHAR(255),                      -- Encrypted signature knowledge key in Base64 format
    signature_knowledge_key_salt       VARCHAR(255),                      -- Signature knowledge key salt in Base64 format
    signature_possession_key           VARCHAR(255),                      -- Signature possession key in Base64 format
    transport_master_key               VARCHAR(255),                      -- Transport master key in Base64 format
    shared_secret_algorithm            VARCHAR(255),                      -- Used shared secret algorithm
    temporary_key_act_sign_request_key VARCHAR(255),                      -- Key for signing temporary key requests in activation scope
    pqc_server_public_key              TEXT,                              -- Server public key (PQC) in Base64 format
    shared_info2_key                   VARCHAR(255),                      -- Key for deriving sharedInfo2 parameter in Base64 format
    mac_personalized_data_key          VARCHAR(255),                      -- MAC personalized data key in Base64 format
    biometry_factor_key                VARCHAR(255),                      -- Biometry factor key in Base64 format
    knowledge_factor_key_encrypted     VARCHAR(255),                      -- Encrypted knowledge factor key in Base64 format
    knowledge_factor_key_salt          VARCHAR(255),                      -- Knowledge factor key salt in Base64 format
    possession_factor_key              VARCHAR(255),                      -- Possession factor key in Base64 format
    encrypted_ec_device_private_key    VARCHAR(255),                      -- Encrypted EC device private key in Base64 format
    encrypted_pqc_device_private_key   TEXT,                              -- Encrypted PQC device private key in Base64 format
    ec_device_public_key               VARCHAR(255),                      -- Device EC public key in Base64 format
    pqc_device_public_key              TEXT,                              -- Device PQC public key in Base64 format
    ec_server_public_key               VARCHAR(255),                      -- Server EC public key in Base64 format
    status_blob_mac_key                VARCHAR(255),                      -- MAC key for status blob in Base64 format
    version                            INTEGER                            -- Version (major)
);
