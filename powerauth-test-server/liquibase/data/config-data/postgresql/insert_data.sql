-- pa cloud property
INSERT INTO pa_cloud_property (name, value)
VALUES ('service.base.url', 'https://pa-test-internal-mtoken-app.azurewebsites.net/powerauth-cloud/');
ON CONFLICT (name) DO NOTHING;

-- es operation templates
INSERT INTO es_operation_template (id, placeholder, language, title, message, attributes, ui)
VALUES
    (nextval('es_operation_template_seq'), 'authorize_payment', 'en', 'Payment Approval',
     'Please confirm the payment', '[
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
       "value": "iban"}
   }
   ]', null),
    (nextval('es_operation_template_seq'), 'login', 'en', 'Login Approval',
     'Are you logging in to the internet banking?', null, null)
    ON CONFLICT (placeholder,language) DO NOTHING;

-- pa operation template
INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type,
    max_failure_count, expiration)
SELECT nextval('pa_operation_template_seq'), 'login', 'login', 'A2', 'possession_knowledge, possession_biometry', 5, 300
WHERE NOT EXISTS (SELECT * FROM pa_operation_template WHERE template_name = 'login' AND operation_type = 'login');

INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type,
    max_failure_count, expiration)
SELECT nextval('pa_operation_template_seq'), 'payment', 'authorize_payment',
    'A1*A${amount}${currency}*I${iban}', 'possession_knowledge, possession_biometry', 5, 300
WHERE NOT EXISTS (SELECT * FROM pa_operation_template WHERE template_name = 'payment' AND operation_type = 'authorize_payment');

-- localization
INSERT INTO pa_cloud_localization (id, placeholder, language, title, summary)
VALUES
    (nextval('pa_cloud_localization_seq'), 'login', 'en', 'Approve Login',
     'Please confirm the login request.'),
    (nextval('pa_cloud_localization_seq'), 'payment', 'en', 'Approve Payment',
     'Please approve the payment of ${amount} ${currency} to account ${iban}.')
ON CONFLICT (placeholder, language) DO NOTHING;

-- admin user
INSERT INTO pa_cloud_user (id, username, password, enabled)
VALUES (nextval('pa_cloud_user_seq'), '${POWERAUTH_CLOUD_ADMIN_USERNAME}', '$2y$12$9ZqXvNsrWTAYqTDMr2JfbOA2Z8G1UVMJIkL8n7eOv29TdZjzZ3gUa', true)
ON CONFLICT (username) DO NOTHING;

INSERT INTO pa_cloud_user_authority (id, user_id, authority)
VALUES (nextval('pa_cloud_user_seq'), (SELECT id FROM pa_cloud_user WHERE username = '${POWERAUTH_CLOUD_ADMIN_USERNAME}'), 'ROLE_ADMIN')
ON CONFLICT (user_id) do nothing;
