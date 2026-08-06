FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS build
ARG SOURCE_URL=https://github.com/apache/guacamole-client/archive/refs/tags/1.6.0.tar.gz
ARG SOURCE_SHA256=de5c489471544f93dfc0cc821cf95805aaf9b84e2e3314b6d52e41aeeffd7c16
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL --retry 3 -o /tmp/src.tar.gz "$SOURCE_URL" \
 && echo "$SOURCE_SHA256  /tmp/src.tar.gz" | sha256sum -c - \
 && mkdir /src && tar -xzf /tmp/src.tar.gz -C /src --strip-components=1
COPY JSONAuthenticationProvider.java /src/extensions/guacamole-auth-json/src/main/java/org/apache/guacamole/auth/json/JSONAuthenticationProvider.java
WORKDIR /src
RUN mvn -B -DskipTests -pl extensions/guacamole-auth-json -am package

FROM guacamole/guacamole:1.6.0@sha256:f344085e618bb05e22b964b0208dbd06d3468275bac70206f93805245e067b40
COPY --from=build /src/extensions/guacamole-auth-json/target/guacamole-auth-json-1.6.0.jar /opt/guacamole/extensions/guacamole-auth-json/guacamole-auth-json.jar
COPY tab-title.js /tmp/tab-title.js
USER root
RUN mkdir /tmp/war-cache-bust && cd /tmp/war-cache-bust \
 && jar xf /opt/guacamole/webapp/guacamole.war index.html \
 && sed -i 's/\.js"><\/script>/\.js?v=json-context-1.0.0"><\/script>/g' index.html \
 && grep -q 'guacamole\..*\.js?v=json-context-1.0.0' index.html \
 && cp /tmp/tab-title.js tab-title.js \
 && sed -i 's#</head>#<script src="tab-title.js?v=rdp-title-1.0.0"></script></head>#' index.html \
 && grep -q 'tab-title.js?v=rdp-title-1.0.0' index.html \
 && jar uf /opt/guacamole/webapp/guacamole.war index.html tab-title.js \
 && rm -rf /tmp/war-cache-bust
USER guacamole
