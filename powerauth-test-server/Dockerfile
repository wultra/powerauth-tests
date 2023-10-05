FROM ibm-semeru-runtimes:open-17.0.8_7-jre
LABEL maintainer="roman.strobl@wultra.com"

# Prepare environment variables
ENV JAVA_HOME=/opt/java/openjdk \
    PKG_RELEASE=1~jammy \
    TOMCAT_HOME=/usr/local/tomcat \
    TOMCAT_MAJOR=10 \
    TOMCAT_VERSION=10.1.13 \
    LOGBACK_CONF=/opt/logback/conf \
    TZ=UTC

ENV PATH=$PATH:$TOMCAT_HOME/bin

# Init
RUN apt-get -y update  \
    && apt-get -y upgrade \
    && apt-get -y install bash curl wget

# Install tomcat
RUN curl -jkSL -o /tmp/apache-tomcat.tar.gz http://archive.apache.org/dist/tomcat/tomcat-${TOMCAT_MAJOR}/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz \
    && [ "406c0c367ac6ad95bb724ecc3a3c340ad7ded8c62287d657811eeec496eaaca1f5add52d2f46111da1426ae67090c543f6deccfeb5fdf4bdae32f9b39e773265  /tmp/apache-tomcat.tar.gz" = "$(sha512sum /tmp/apache-tomcat.tar.gz)" ] \
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

# Docker configuration
EXPOSE 8080
STOPSIGNAL SIGQUIT

USER powerauth

COPY deploy/conf/logback/* $LOGBACK_CONF/

CMD ["catalina.sh", "run"]
