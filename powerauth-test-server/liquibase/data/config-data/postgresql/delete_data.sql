-- pa cloud property
DELETE FROM pa_cloud_property
WHERE name like 'name';

-- es operation templates
DELETE FROM es_operation_template
WHERE placeholder in ('authorize_payment', 'login') and language in ('en');

-- pa operation template
DELETE FROM pa_operation_template
WHERE template_name in ('login', 'payment') and operation_type in ('login', 'authorize_payment');

-- localization
DELETE FROM pa_cloud_localization
WHERE placeholder in ('login', 'payment') and language in ('en');

-- admin user
DELETE FROM pa_cloud_user_authority
WHERE user_id in (SELECT id FROM pa_cloud_user WHERE username like 'rf-admin');

DELETE pa_cloud_user
    WHERE username like 'rf-admin';