FROM ibm-semeru-runtimes:open-21.0.7_6-jre
LABEL maintainer="roman.strobl@wultra.com"

# Prepare environment variables
ENV JAVA_HOME=/opt/java/openjdk \
    PKG_RELEASE=1~jammy \
    LB_HOME=/usr/local/liquibase \
    LB_VERSION=4.30.0 \
    TOMCAT_HOME=/usr/local/tomcat \
    TOMCAT_MAJOR=10 \
    TOMCAT_VERSION=10.1.42 \
    TOMCAT_ARCHIVE_SHA512=eb09be6df829ebc1fb8851282888966101e878b2c4a507623f3acabc2a1337b89271b4ad7b9361f0bf4bcfe7b5cfec93617bd716043c68afef029c080fff6546 \
    LOGBACK_CONF=/opt/logback/conf \
    TZ=UTC

ENV PATH=$PATH:$LB_HOME:$TOMCAT_HOME/bin

# Init
RUN apt-get -y update  \
    && apt-get -y upgrade \
    && apt-get -y install bash curl wget

# Install tomcat
RUN curl -jkSL -o /tmp/apache-tomcat.tar.gz http://archive.apache.org/dist/tomcat/tomcat-${TOMCAT_MAJOR}/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz \
    && [ "$TOMCAT_ARCHIVE_SHA512  /tmp/apache-tomcat.tar.gz" = "$(sha512sum /tmp/apache-tomcat.tar.gz)" ] \
    && gunzip /tmp/apache-tomcat.tar.gz \
    && tar -C /opt -xf /tmp/apache-tomcat.tar \
    && ln -s /opt/apache-tomcat-$TOMCAT_VERSION $TOMCAT_HOME

# Clear root context
RUN rm -rf $TOMCAT_HOME/webapps/*

# Add valve for proxy with SSL termination
RUN sed -i 's/<\/Host>/<Valve className="org.apache.catalina.valves.RemoteIpValve" remoteIpHeader="X-Forwarded-For" protocolHeader="X-Forwarded-Proto"\/><\/Host>/' $TOMCAT_HOME/conf/server.xml
# Add valve for health check
RUN sed -i 's/<\/Host>/<Valve className="org.apache.catalina.valves.HealthCheckValve" \/><\/Host>/' $TOMCAT_HOME/conf/server.xml

# Deploy and run applications
COPY docker/powerauth-test-server.xml $TOMCAT_HOME/conf/Catalina/localhost/
COPY target/powerauth-test-server-*.war $TOMCAT_HOME/webapps/powerauth-test-server.war

# Add PowerAuth User
RUN groupadd -r powerauth \
    && useradd -r -g powerauth -s /sbin/nologin powerauth \
    && chown -R powerauth:powerauth $TOMCAT_HOME \
    && chown -R powerauth:powerauth /opt/apache-tomcat-$TOMCAT_VERSION

# Liquibase - binaries
# This setup was inspired by https://github.com/mobtitude/liquibase/blob/master/Dockerfile
RUN set -x \
    && wget -q -O /tmp/liquibase.tar.gz "https://github.com/liquibase/liquibase/releases/download/v$LB_VERSION/liquibase-$LB_VERSION.tar.gz" \
    && [ "184ffd609518091da42d6cd75e883b4f6ff1763cce8883e95fc99f7f05ca262d  /tmp/liquibase.tar.gz" = "$(sha256sum /tmp/liquibase.tar.gz)" ] \
    && mkdir -p "$LB_HOME" \
    && tar -xzf /tmp/liquibase.tar.gz -C "$LB_HOME" \
    && rm -rf "$LB_HOME/sdk" \
# Uninstall packages which are no longer needed and clean apt caches
    && apt-get -y remove wget curl gettext-base \
    && apt-get -y purge --auto-remove \
    && rm -rf /tmp/* /var/cache/apt/*

# Liquibase - changesets
RUN rm -rf $LB_HOME/data
COPY deploy/liquibase/data $LB_HOME/data

# Docker configuration
EXPOSE 8080
STOPSIGNAL SIGQUIT

USER powerauth

COPY deploy/conf/logback/* $LOGBACK_CONF/
COPY deploy/docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
