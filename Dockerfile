FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY target/your-app.jar app.jar

# Don't hardcode sensitive values here!
# Use environment variables instead
ENTRYPOINT ["java", \
    "-Dserver.host=${SERVER_HOST:-0.0.0.0}", \
    "-Dserver.port=${SERVER_PORT:-8080}", \
    "-Dstorage.path=${STORAGE_PATH:-data/articles}", \
    "-Dcms.username=${CMS_USERNAME}", \
    "-Dcms.password=${CMS_PASSWORD}", \
    "-jar", "app.jar"]