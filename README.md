# Georgia News

A news site for Georgia (the country), written in plain Java with no external dependencies. It runs on the JDK's own HttpServer, stores articles as JSON files on disk, and renders the HTML itself, no templating library, no frontend framework, nothing fetched from npm.

Articles are served as plain HTML from a file-backed repository: each one lives as its own JSON file under `data/articles`, deleting an article moves it to `data/archive` instead of removing it outright, and pages are generated fresh on each request rather than built ahead of time. A built-in CMS, protected by basic auth with CSRF-protected forms, handles writing, editing, and publishing articles.

## Running it

Running the jar directly falls back to sensible defaults (port 8080, username `admin`, password `changeme`), so it's worth at least overriding the password:

```bash
mvn clean package
java -Dcms.password=yourpassword -jar target/georgia-news-1.0-SNAPSHOT.jar
```

The Docker image doesn't have those defaults baked in, so all five environment variables need to be set or the container won't start:

```bash
docker build -t georgia-news .
docker run -p 8080:8080 \
  -e SERVER_HOST=0.0.0.0 \
  -e SERVER_PORT=8080 \
  -e STORAGE_PATH=data/articles \
  -e CMS_USERNAME=admin \
  -e CMS_PASSWORD=yourpassword \
  georgia-news
```
