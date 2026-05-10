FROM ibm-semeru-runtimes:open-21.0.8_9-jre

LABEL maintainer="Wultra <hello@wultra.com>"

# Prepare environment variables
ENV JAVA_HOME=/opt/java/openjdk \
    LB_HOME=/usr/local/liquibase \
    LB_VERSION=4.33.0 \
    LB_ARCHIVE_SHA256=689acfcdc97bad0d4c150d1efab9c851e251b398cb3d6326f75e8aafe40ed578 \
    OJDBC_SHA256=756663c916f64e94659c197768f5c7a29706bc0fd4274dfdf88f474885516d06 \
    PKG_RELEASE=1~jammy \
    LOGBACK_CONF=/opt/logback/conf \
    TZ=UTC \
    APP_PATH="/app/powerauth-test-server.war" \
    EXTLIB_PATH="/app/extlib" \
    OJDBC_VERSION="23.8.0.25.04" \
    LQ_ENABLED=true

ENV PATH=$PATH:$LB_HOME

# Upgrade OS and dependencies
RUN apt-get -y update  \
    && apt-get -y upgrade \
    && apt-get -y install bash wget \
# Install Liquibase, inspired by https://github.com/mobtitude/liquibase/blob/master/Dockerfile
    && set -x \
    && mkdir -p ${EXTLIB_PATH} \
    # Download OJDBC driver
    && wget --no-verbose https://repo1.maven.org/maven2/com/oracle/database/jdbc/ojdbc11/${OJDBC_VERSION}/ojdbc11-${OJDBC_VERSION}.jar -O ${EXTLIB_PATH}/ojdbc11.jar \
    # This ensures file integrity by comparing the actual hash with the expected hash ($OJDBC_SHA256).
    && [ "$OJDBC_SHA256  ${EXTLIB_PATH}/ojdbc11.jar" = "$(sha256sum ${EXTLIB_PATH}/ojdbc11.jar)" ] \
    # Download Liquibase
    && wget -q -O /tmp/liquibase.tar.gz "https://github.com/liquibase/liquibase/releases/download/v$LB_VERSION/liquibase-$LB_VERSION.tar.gz" \
    && [ "$LB_ARCHIVE_SHA256  /tmp/liquibase.tar.gz" = "$(sha256sum /tmp/liquibase.tar.gz)" ] \
    && mkdir -p "$LB_HOME" \
    && tar -xzf /tmp/liquibase.tar.gz -C "$LB_HOME" \
    && rm -rf "$LB_HOME/sdk" "$LB_HOME/examples" \
# Uninstall packages which are no longer needed and clean apt caches
    && apt-get -y remove wget gettext-base \
    && apt-get -y purge --auto-remove \
    && rm -rf /tmp/* /var/cache/apt/* \
# Remove default Liquibase data
    && rm -rf "$LB_HOME/data" \
# Add PowerAuth user
    && groupadd -r powerauth && useradd -r -g powerauth -s /sbin/nologin powerauth

# Copy new Liquibase data
COPY docs/db/changelog/changesets/powerauth-test-server $LB_HOME/db/changelog

# Deploy and run applications
COPY ./powerauth-test-server/target/powerauth-test-server*.war "${APP_PATH}"

# Docker configuration
EXPOSE 8080
STOPSIGNAL SIGQUIT

# Add PowerAuth User
USER powerauth

COPY ./powerauth-test-server/docker/deploy/conf/logback/* $LOGBACK_CONF/
COPY ./powerauth-test-server/docker/docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]