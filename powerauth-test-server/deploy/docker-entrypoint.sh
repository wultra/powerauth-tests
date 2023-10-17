#!/usr/bin/env sh

liquibase --headless=true --log-level=INFO --changeLogFile=$LB_HOME/data/powerauth-test-server/db.changelog-module.xml --username=$POWERAUTH_SERVER_DATASOURCE_USERNAME --password=$POWERAUTH_SERVER_DATASOURCE_PASSWORD --url=$POWERAUTH_SERVER_DATASOURCE_URL update

nginx

catalina.sh run
