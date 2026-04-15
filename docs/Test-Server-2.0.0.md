# Migration from 1.10.x to 2.0.0

This guide contains instructions for migration from Test Server version `1.10.x` to version `2.0.0`.

## Cryptography Protocol Upgrade

The PowerAuth protocol version has been increased to `4.0`.

In case you configured a specific protocol version for the Test Server, update the configuration using application properties to version `4.0`: 

```properties
powerauth.version=4.0
```

## Database Schema Changes

Due to migration to new post-quantum cryptography algorithms, the following database changes were introduced. Test server uses Liquibase to handle database schema changes, thus these database schema changes will be applied automatically using Liquibase.

### Changes in Table pa_test_config
- Added column `mobile_sdk_config` in table `pa_test_config` to store mobile SDK configuration.
- The column `master_public_key` in table `pa_test_config` is nullable now.

### Changes in  Table pa_test_status
- Added column `shared_secret_algorithm` in table `pa_test_status` for storing the used shared secret algorithm.
- Added column `temporary_key_act_sign_request_key` in table `pa_test_status` for storing the temporary key request signing key.
- Added column `pqc_server_public_key` in table `pa_test_status` for storing the PQC server public key.
- Added column `shared_info2_key` in table `pa_test_status` for storing the SharedInfo2 key.
- Added column `mac_personalized_data_key` in table `pa_test_status` for storing the personalized data MAC key.
- Added column `biometry_factor_key` in table `pa_test_status` for storing the biometry factor key.
- Added column `knowledge_factor_key_encrypted` in table `pa_test_status` for storing the encrypted knowledge factor key.
- Added column `knowledge_factor_key_salt` in table `pa_test_status` for storing the knowledge factor key salt.
- Added column `possession_factor_key` in table `pa_test_status` for storing the possession factor key.
- Added column `encrypted_ec_device_private_key` in table `pa_test_status` for storing the encrypted EC device private key.
- Added column `encrypted_pqc_device_private_key` in table `pa_test_status` for storing the encrypted PQC device private key.
- Added column `ec_device_public_key` in table `pa_test_status` for storing the EC device public key.
- Added column `pqc_device_public_key` in table `pa_test_status` for storing the PQC device public key.
- Added column `ec_server_public_key` in table `pa_test_status` for storing the EC server public key.
- Added column `status_blob_mac_key` in table `pa_test_status` for storing the status blob MAC key.
- Added column `version` in table `pa_test_status` for storing the cryptography protocol version.

### Deprecated Columns in Table pa_test_status
- The column `server_public_key` in table `pa_test_status` is nullable now (deprecated).
- The column `encrypted_device_private_key` in table `pa_test_status` is nullable now (deprecated).
- The column `signature_biometry_key` in table `pa_test_status` is nullable now (deprecated).
- The column `signature_knowledge_key_encrypted` in table `pa_test_status` is nullable now (deprecated).
- The column `signature_knowledge_key_salt` in table `pa_test_status` is nullable now (deprecated).
- The column `signature_possession_key` in table `pa_test_status` is nullable now (deprecated).
- The column `transport_master_key` in table `pa_test_status` is nullable now (deprecated).

## Impact of Database Schema Changes on Existing Activations

In case you use long-term activations which are used for tests with version 3 of the cryptography protocol, such activations cannot be used for tests with version 4 of the cryptography protocol. Unlike in the mobile SDK, the upgrade process is not supported in the test server. You should delete old activations with version 3 of cryptography protocol (all previous Test Server versions) and recreate the activations using version 4 of cryptography protocol (current version). Only then the new cryptographic material in table `pa_test_status` will be correctly stored and available for the tests.  

## REST API Changes

- Signature endpoints `/signature` are deprecated, use the `/auth` prefix instead.
- In endpoint `/signature/compute-online`, the request parameter `signatureType` is deprecated, use `authenticationCodeType` instead.
- In endpoint `/token/create`, the request parameter `signatureType` is deprecated, use `authenticationCodeType` instead.
- In endpoint `/operations/approve`, the request parameter `signatureType` is deprecated, use `authenticationCodeType` instead.
- In endpoint `/activation/create`, you can specify new request parameter `confirmActivation` which controls whether activation gets confirmed and parameter `enableBiometry` which enables biometry during the confirmation.
- In endpoint `/activation/create`, you can specify request parameter `algorithm` which specifies the algorithm used for the activation (e.g. `EC_P384_ML_L3` or `EC_P384_ML_L5`).
- In endpoint `/activation/create`, there is a new response parameter `confirmed` which indicates whether activation was confirmed.

### Unsupported Authentication Code Types

Following authentication code types and signature types are no longer supported:
- `KNOWLEDGE`
- `BIOMETRY`
- `POSSESSION_KNOWLEDGE_BIOMETRY`

This change affects following endpoints:
- `POST /signature/compute-online`
- `POST /auth/compute-online`
- `POST /operations/approve`
