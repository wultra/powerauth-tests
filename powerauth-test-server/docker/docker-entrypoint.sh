#!/usr/bin/env bash
set -euo pipefail

if [ "${LQ_ENABLED}" = true ]; then
  liquibase --headless=true --log-level=INFO --changeLogFile="${LB_HOME}/data/powerauth-test-server/db.changelog-module.xml" --username="${POWERAUTH_TEST_SERVER_DATASOURCE_USERNAME}" --password="${POWERAUTH_TEST_SERVER_DATASOURCE_PASSWORD}" --url="${POWERAUTH_TEST_SERVER_DATASOURCE_URL}" update
fi

catalina.sh run
