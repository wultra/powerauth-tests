# Performance Testing Guide

This document serves as an internal guide for running performance tests.

## DB preparation

Before running the tests there are several steps that need to be taken:

### 1. Create Admin User in PAC

Postgresql

```sql
INSERT INTO pa_cloud_user (id, username, userpassword, enabled)
    VALUES (nextval('pa_cloud_user_seq'), 'system-admin', '{GENERATED_PWD_ENCODED}', true);

INSERT INTO pa_cloud_user_authority (id, user_id, authority)
   VALUES (nextval('pa_cloud_user_seq'), (SELECT id FROM pa_cloud_user WHERE username = 'system-admin'), 'ROLE_ADMIN');
```

MSSQL

```sql
INSERT INTO pa_cloud_user (id, username, userpassword, enabled) 
   VALUES (NEXT VALUE FOR pa_cloud_user_seq, 'system-admin', '{GENERATED_PWD_ENCODED}', 1);

INSERT INTO pa_cloud_user_authority (id, user_id, authority)
   VALUES (NEXT VALUE FOR pa_cloud_user_seq, (SELECT id FROM pa_cloud_user WHERE username = 'system-admin'), 'ROLE_ADMIN');
```

ORACLE

```sql
INSERT INTO pa_cloud_user (ID, USERNAME, userpassword, ENABLED)
   SELECT pa_cloud_user_seq.NEXTVAL, 'system-admin', '{GENERATED_PWD_ENCODED}', 1 FROM DUAL;
    INSERT INTO pa_cloud_user_authority (id, user_id, authority)
        SELECT pa_cloud_user_seq.NEXTVAL, id, 'ROLE_ADMIN'
        FROM pa_cloud_user
        WHERE username = 'system-admin';
```

To create the password follow steps
from https://developers.wultra.com/components/powerauth-cloud/develop/documentation/

### 2. Create template in pa_operation_template

Postgresql

```sql
INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration)
    VALUES (1, 'login', 'login', 'A2', 'possession_knowledge,possession_biometry', 5, 300);

INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration)
    VALUES (2, 'payment', 'authorize_payment', 'A1*A${amount}${currency}*I${iban}', 'possession_knowledge,possession_biometry', 5, 300);
```

MSSQL

```sql
INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration) 
    VALUES (1, 'login', 'login', 'A2', 'possession_knowledge,possession_biometry', 5, 300);

INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration)
    VALUES (2, 'payment', 'authorize_payment', 'A1*A${amount}${currency}*I${iban}', 'possession_knowledge,possession_biometry', 5, 300);
```

ORACLE

```sql
INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration)
    VALUES (1, 'login', 'login', 'A2', 'possession_knowledge,possession_biometry', 5, 300);

INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration)
    VALUES (2, 'payment', 'authorize_payment', 'A1*A${amount}${currency}*I${iban}', 'possession_knowledge,possession_biometry', 5, 300);
```

### 3. Create operation summary localization

Postgresql

```sql
INSERT INTO pa_cloud_localization (id, placeholder, language, title, summary)
   VALUES (1, 'login', 'en', 'Approve Login', 'Please confirm the login request.');

INSERT INTO pa_cloud_localization (id, placeholder, language, title, summary)
    VALUES (2, 'payment', 'en', 'Approve Payment', 'Please approve the payment of ${amount} ${currency} to account ${iban}.');
```

MSSQL

```sql
INSERT INTO pa_cloud_localization (id, placeholder, language, title, summary)
    VALUES (1, 'login', 'en', 'Approve Login', 'Please confirm the login request.');

INSERT INTO pa_cloud_localization (id, placeholder, language, title, summary)
    VALUES (2, 'payment', 'en', 'Approve Payment', 'Please approve the payment of ${amount} ${currency} to account ${iban}.');
```

ORACLE

```sql
INSERT INTO pa_cloud_localization (id, placeholder, language, title, summary)
    VALUES (1, 'login', 'en', 'Approve Login', 'Please confirm the login request.');

INSERT INTO pa_cloud_localization (id, placeholder, language, title, summary)
    VALUES (2, 'payment', 'en', 'Approve Payment', 'Please approve the payment of ${amount} ${currency} to account ${iban}.');
```

### 4. Create mobile token operation localization

Postgresql

```sql
INSERT INTO es_operation_template (id, placeholder, language, title, message, attributes, ui)
    VALUES (1, 'login', 'en', 'Login Approval', 'Are you logging in to the internet banking?', null, null);

INSERT INTO es_operation_template (id, placeholder, language, title, message, attributes, ui)
    VALUES (2, 'authorize_payment', 'en', 'Payment Approval', 'Please confirm the payment', '[
   {
    "id": "operation.amount",
    "type": "AMOUNT",
    "text": "Amount",
    "params": {
      "amount": "amount",
      "currency": "currency"
    }
   },
   {
    "id": "operation.account",
    "type": "KEY_VALUE",
    "text": "To Account",
    "params": {
      "value": "iban"
    }
   }
   ]', null);
```

MSSQL

```sql
INSERT INTO es_operation_template (id, placeholder, language, title, message, attributes, ui)
    VALUES (1, 'login', 'en', 'Login Approval', 'Are you logging in to the internet banking?', NULL, NULL);

INSERT INTO es_operation_template (id, placeholder, language, title, message, attributes, ui)
    VALUES (2, 'authorize_payment', 'en', 'Payment Approval', 'Please confirm the payment', '[
   {
    "id": "operation.amount",
    "type": "AMOUNT",
    "text": "Amount",
    "params": {
      "amount": "amount",
      "currency": "currency"
    }
   },
   {
    "id": "operation.account",
    "type": "KEY_VALUE",
    "text": "To Account",
    "params": {
      "value": "iban"
    }
   }
   ]', NULL);
```

Oracle

```sql
INSERT INTO es_operation_template (id, placeholder, language, title, message, attributes, ui)
    VALUES (1, 'login', 'en', 'Login Approval', 'Are you logging in to the internet banking?', NULL, NULL);

INSERT INTO es_operation_template (id, placeholder, language, title, message, attributes, ui)
    VALUES (2, 'authorize_payment', 'en', 'Payment Approval', 'Please confirm the payment', '[{"id": "operation.amount", "type": "AMOUNT", "text": "Amount", "params": {"amount": "amount", "currency": "currency"}}, {"id": "operation.account", "type": "KEY_VALUE", "text": "To Account", "params": {"value": "iban"}}]', NULL);
```

## Running the tests

To run the tests we use maven gatling plugin. The methodology of the tests is as follows. There are two simulations:

- Data Preparation
- Performance Test

There is a config file [.perf_test_config](./../powerauth-load-tests/src/test/resources/.perf_test_config) which needs
to be sourced before running the tests. This file serves as a configuration file for the testing. More information about
possible parameters to set is inside the file.

Before running the Performance Test Simulation, which is essentially a load test, **the Data Preparation needs to be run
at least once to populate the db with some data**. It also generates a JSON file
to `powerauth-load-tests/src/test/resources` which holds information that is used during the Performance Test.

One may use prepared scripts to easily trigger the tests:

- [run_perf_tests.sh](./../powerauth-load-tests/src/test/resources/run_perf_tests.sh)
- [run_data_prepare.sh](./../powerauth-load-tests/src/test/resources/run_data_prepare.sh)

The reports are by default generated to `/results/`.

## Useful

- Link to Gatling docs - https://docs.gatling.io

- Generating reports from failed/unfinished tests
  ```bash
  mvn gatling:test -Dgatling.reportsOnly={PATH_TO_SIMULATION_OUTPUT_FOLDER}
  ```
