FROM ibm-semeru-runtimes:open-17.0.6_10-jre
LABEL maintainer="roman.strobl@wultra.com"

# Prepare environment variables
ENV JAVA_HOME=/opt/java/openjdk \
    PKG_RELEASE=1~jammy \
    TOMCAT_HOME=/usr/local/tomcat \
    TOMCAT_MAJOR=10 \
    TOMCAT_VERSION=10.1.7 \
    LOGBACK_CONF=/opt/logback/conf \
    TZ=UTC

ENV PATH=$PATH:$TOMCAT_HOME/bin

# Init
RUN apt-get -y update  \
    && apt-get -y upgrade \
    && apt-get -y install bash curl wget

# Install tomcat
RUN curl -jkSL -o /tmp/apache-tomcat.tar.gz http://archive.apache.org/dist/tomcat/tomcat-${TOMCAT_MAJOR}/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.tar.gz \
    && [ "41997f90baf86af6dc0396cbf66941f801e0ae9ad1b57475661d10e648c55559491e85468af2df3ee457be3fcae12b74537ce19a9a28e34030b98e8bb38dbd35  /tmp/apache-tomcat.tar.gz" = "$(sha512sum /tmp/apache-tomcat.tar.gz)" ] \
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
