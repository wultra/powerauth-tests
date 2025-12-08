FROM liquibase:4.33.0-alpine

LABEL maintainer="Wultra <hello@wultra.com>"

COPY ./powerauth-test-server/docker/deploy/db/changelog /liquibase/changelog
COPY ./powerauth-test-server/docker-init/docker-entrypoint.sh /docker-entrypoint.sh

USER liquibase
ENTRYPOINT ["/docker-entrypoint.sh"]
