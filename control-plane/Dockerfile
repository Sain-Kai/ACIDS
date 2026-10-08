FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline || true
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:21-jre
USER root
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home sentinelmesh \
    && mkdir -p /var/log/sentinelmesh /app/audit \
    && chown -R sentinelmesh:sentinelmesh /var/log/sentinelmesh /app/audit
WORKDIR /app
COPY --from=build /src/target/control-plane-0.1.0-SNAPSHOT.jar /app/control-plane.jar
USER 10001
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/control-plane.jar"]
