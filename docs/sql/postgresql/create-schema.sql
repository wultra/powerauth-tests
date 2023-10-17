CREATE TABLE pa_test_config
(
    application_id     VARCHAR(255) NOT NULL PRIMARY KEY, -- Application identifier
    application_name   VARCHAR(255) NOT NULL,             -- Application name
    application_key    VARCHAR(255) NOT NULL,             -- Application key
    application_secret VARCHAR(255) NOT NULL,             -- Application secret
    master_public_key  VARCHAR(255) NOT NULL              -- Master public key in Base64 format
);

CREATE TABLE pa_test_status
(
    activation_id                     VARCHAR(255) NOT NULL PRIMARY KEY, -- Activation identifier
    server_public_key                 VARCHAR(255) NOT NULL,             -- Server public key in Base64 format
    counter                           INTEGER      NOT NULL,             -- Numeric counter
    ctr_data                          VARCHAR(255) NOT NULL,             -- Hashed counter data
    encrypted_device_private_key      VARCHAR(255) NOT NULL,             -- Encrypted device private key in Base64 format
    signature_biometry_key            VARCHAR(255) NOT NULL,             -- Signature biometry key in Base64 format
    signature_knowledge_key_encrypted VARCHAR(255) NOT NULL,             -- Encrypted signature knowledge key in Base64 format
    signature_knowledge_key_salt      VARCHAR(255) NOT NULL,             -- Signature knowledge key in Base64 format
    signature_possession_key          VARCHAR(255) NOT NULL,             -- Signature possession key in Base64 format
    transport_master_key              VARCHAR(255) NOT NULL              -- Transport master key in Base64 format
);
