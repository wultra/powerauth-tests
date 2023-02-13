-- pa cloud property
DELETE FROM pa_cloud_property
WHERE name = 'service.base.url' AND value = '${pa-cloud-service-base-url}';

-- es operation templates
DELETE FROM es_operation_template
WHERE placeholder IN ('authorize_payment', 'login') AND language IN ('en');

-- pa operation template
DELETE FROM pa_operation_template
WHERE template_name IN ('login', 'payment') AND operation_type IN ('login', 'authorize_payment');

-- localization
DELETE FROM pa_cloud_localization
WHERE placeholder IN ('login', 'payment') AND language IN ('en');

-- admin user
DELETE FROM pa_cloud_user_authority
WHERE user_id IN (SELECT id FROM pa_cloud_user WHERE username = '${pa-admin-username}');

DELETE FROM pa_cloud_user
WHERE username = '${pa-admin-username}';