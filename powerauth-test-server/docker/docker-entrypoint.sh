#!/usr/bin/env sh

liquibase --headless=true --log-level=INFO --changeLogFile=$LB_HOME/data/changelog.xml --username=$POWERAUTH_CLOUD_DATASOURCE_USERNAME --password=$POWERAUTH_CLOUD_DATASOURCE_PASSWORD --url=$POWERAUTH_CLOUD_DATASOURCE_URL update

catalina.sh run
