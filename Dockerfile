FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

# Copy any JAR file from target directory
COPY target/georgia-news-1.0-SNAPSHOT.jar app.jar

ENTRYPOINT ["java", "-Dserver.host=${SERVER_HOST:-0.0.0.0}", "-Dserver.port=${SERVER_PORT:-8080}", "-Dstorage.path=${STORAGE_PATH:-data/articles}", "-Dcms.username=${CMS_USERNAME}", "-Dcms.password=${CMS_PASSWORD}", "-jar", "app.jar"]
EXPOSE 8080