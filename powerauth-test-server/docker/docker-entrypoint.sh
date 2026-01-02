#!/usr/bin/env bash
set -euo pipefail

if [ "${LQ_ENABLED}" = true ]; then
  liquibase --headless=true --log-level=INFO --changeLogFile="${LB_HOME}/data/powerauth-test-server/db.changelog-module.xml" --username="${POWERAUTH_TEST_SERVER_DATASOURCE_USERNAME}" --password="${POWERAUTH_TEST_SERVER_DATASOURCE_PASSWORD}" --url="${POWERAUTH_TEST_SERVER_DATASOURCE_URL}" update
fi

exec java -Dserver.port=8080 -Dspring.config.additional-location=/app/application.properties ${JAVA_OPTS:-} -Dserver.servlet.context-path=/powerauth-test-server -cp "${APP_PATH}:/app/extlib/*" org.springframework.boot.loader.launch.WarLauncher
