FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
COPY src src
RUN mvn -q -DskipTests package
FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 appuser
RUN mkdir -p /var/lib/authplatform && chown appuser:appuser /var/lib/authplatform
WORKDIR /app
COPY --from=build /workspace/target/authplatform-*.jar app.jar
USER appuser
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
