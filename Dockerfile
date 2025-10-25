FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

# Copy any JAR file from target directory
COPY target/georgia-news-1.0-SNAPSHOT.jar app.jar

ENTRYPOINT ["sh", "-c", "java -Dserver.host=${SERVER_HOST} -Dserver.port=${SERVER_PORT} -Dstorage.path=${STORAGE_PATH} -Dcms.username=${CMS_USERNAME} -Dcms.password=${CMS_PASSWORD} -jar app.jar"]
EXPOSE 8080