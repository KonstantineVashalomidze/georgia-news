package com.github.konstantinevashalomidze;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Core domain model for an article.
 *
 * Represents a published article with metadata and content.
 * Articles are immutable once created (use builder pattern for construction).
 *
 * Fields:
 * - id: Unique identifier (UUID format recommended)
 * - title: Article title (max 200 chars, required, HTML-escaped)
 * - slug: URL-friendly identifier (lowercase, hyphens, unique, matches [a-z0-9-]+)
 * - content: HTML content (required, sanitized, no script tags)
 * - summary: Brief description (max 500 chars, optional, plain text)
 * - author: Author name (required, HTML-escaped)
 * - publishedAt: Publication timestamp (required, ISO-8601 format)
 * - updatedAt: Last modification timestamp (optional, ISO-8601 format)
 * - published: Publication status (true = visible to public, false = draft)
 * - tags: List of category tags (optional, each tag max 50 chars, lowercase)
 */
interface Article {
    String getId();
    String getTitle();
    String getSlug();
    String getContent();
    String getSummary();
    String getAuthor();
    LocalDateTime getPublishedAt();
    LocalDateTime getUpdatedAt();
    boolean isPublished();
    List<String> getTags();
}

/**
 * Repository for article persistence and retrieval.
 *
 * Handles all database/file operations for articles.
 * Thread-safe implementation required for concurrent HTTP requests.
 * Uses file-based storage (JSON or similar) - no external database needed.
 *
 * Storage format: JSON files in /data/articles/ directory
 * - One file per article: {slug}.json
 * - Index file: articles-index.json (contains metadata for listing)
 *
 * Preconditions:
 * - Storage directory must be writable
 * - Article ID must be unique
 * - Slug must be unique across all articles
 *
 * Postconditions:
 * - Saved articles are immediately available for retrieval
 * - Failed saves throw IOException
 * - Deleted articles are moved to /data/archive/ (soft delete)
 */
interface ArticleRepository {
    /**
     * Saves a new article or updates existing one.
     * @param article Article to save (must not be null)
     * @throws IOException if storage operation fails
     * @throws IllegalArgumentException if article validation fails
     */
    void save(Article article) throws IOException;

    /**
     * Finds article by unique slug.
     * @param slug URL-friendly identifier (must match [a-z0-9-]+)
     * @return Optional containing article if found, empty otherwise
     * @throws IOException if read operation fails
     */
    Optional<Article> findBySlug(String slug) throws IOException;

    /**
     * Lists all published articles, sorted by publishedAt descending.
     * @return List of published articles (never null, may be empty)
     * @throws IOException if read operation fails
     */
    List<Article> findAllPublished() throws IOException;

    /**
     * Lists all articles including drafts, sorted by updatedAt descending.
     * Used by CMS only.
     * @return List of all articles (never null, may be empty)
     * @throws IOException if read operation fails
     */
    List<Article> findAll() throws IOException;

    /**
     * Deletes article by slug (soft delete - moves to archive).
     * @param slug Article slug to delete
     * @return true if deleted, false if not found
     * @throws IOException if delete operation fails
     */
    boolean delete(String slug) throws IOException;
}

/**
 * Generates HTML for article pages.
 *
 * Creates complete HTML documents with minimal CSS styling.
 * Style: Plain 90s-style HTML with semantic markup, no JavaScript.
 * Layout: Single column, max-width 800px, centered, responsive.
 *
 * CSS Guidelines:
 * - System fonts only (serif for body, monospace for code)
 * - No external stylesheets or frameworks
 * - Minimal inline styles (< 50 lines total)
 * - Colors: black text on white background, blue links
 * - Responsive: scales naturally with viewport, no media queries needed
 *
 * HTML Structure:
 * - Semantic HTML5 tags (article, header, main, nav)
 * - Proper heading hierarchy (h1 -> h2 -> h3)
 * - UTF-8 encoding, proper DOCTYPE
 * - Meta tags: viewport, description, author
 */
interface ArticleRenderer {
    /**
     * Renders full article page with header, content, and footer.
     * @param article Article to render (must not be null, must be published)
     * @return Complete HTML document as UTF-8 string
     * @throws IllegalArgumentException if article is null or unpublished
     */
    String renderArticlePage(Article article);

    /**
     * Renders homepage with list of recent articles.
     * Shows title, summary, author, date for each article.
     * @param articles List of articles to display (max 50, sorted by date)
     * @return Complete HTML document as UTF-8 string
     */
    String renderHomePage(List<Article> articles);

    /**
     * Renders 404 error page with helpful navigation.
     * @return Complete HTML document as UTF-8 string
     */
    String render404Page();

    /**
     * Renders generic error page for 500 errors.
     * @param message Error message to display (HTML-escaped)
     * @return Complete HTML document as UTF-8 string
     */
    String renderErrorPage(String message);
}

/**
 * HTTP request handler for article routes.
 *
 * Handles GET requests for article pages and homepage.
 * Routes:
 * - GET / -> Homepage with article list
 * - GET /article/{slug} -> Individual article page
 * - GET /static/* -> Static resources (CSS if needed)
 *
 * HTTP Status Codes:
 * - 200 OK: Successful article retrieval
 * - 404 Not Found: Article not found or invalid slug
 * - 500 Internal Server Error: Server error during processing
 * - 405 Method Not Allowed: Non-GET requests
 *
 * Headers:
 * - Content-Type: text/html; charset=UTF-8
 * - Cache-Control: public, max-age=3600 (articles are mostly static)
 * - X-Content-Type-Options: nosniff (security)
 *
 * Preconditions:
 * - HttpExchange must not be null
 * - Request method checked before processing
 *
 * Postconditions:
 * - Response always sent (even on error)
 * - Response stream always closed
 * - Proper status code set
 */
interface ArticleHandler {
    /**
     * Handles incoming HTTP request for articles.
     * @param exchange HttpExchange from com.sun.net.httpserver (must not be null)
     * @throws IOException if response writing fails
     */
    void handle(HttpExchange exchange) throws IOException;
}

/**
 * CMS interface for article management (editor, preview, publishing).
 *
 * Web-based CMS accessible at /cms/* routes.
 * Authentication: Basic HTTP auth with configurable username/password.
 *
 * Routes:
 * - GET /cms -> Article list (all articles including drafts)
 * - GET /cms/new -> New article form
 * - GET /cms/edit/{slug} -> Edit existing article
 * - POST /cms/save -> Save article (create or update)
 * - POST /cms/delete/{slug} -> Delete article
 * - GET /cms/preview/{slug} -> Live preview of article
 *
 * Editor Features:
 * - Textarea for content (HTML input)
 * - Live preview in separate panel (split view or tab)
 * - Title, slug, summary, author fields
 * - Tag input (comma-separated)
 * - Publish/Draft toggle
 * - Character counters for title/summary
 *
 * Security:
 * - CSRF tokens for POST requests
 * - Input sanitization (strip script tags, validate lengths)
 * - Authentication required for all CMS routes
 *
 * Preconditions:
 * - Valid authentication credentials provided
 * - CSRF token matches for POST requests
 * - Slug must be unique when creating new article
 *
 * Postconditions:
 * - Successful saves return 302 redirect to article list
 * - Validation errors return 400 with error messages
 * - Authentication failures return 401 Unauthorized
 */
interface CMSHandler {
    /**
     * Handles CMS HTTP requests.
     * @param exchange HttpExchange from com.sun.net.httpserver (must not be null)
     * @throws IOException if response writing fails
     */
    void handle(HttpExchange exchange) throws IOException;
}

/**
 * Renders CMS HTML pages.
 *
 * Similar to ArticleRenderer but for CMS interface.
 * Style: Functional forms with basic styling, accessible.
 *
 * Layout:
 * - Form-based interface with clear labels
 * - Split-pane editor (content on left, preview on right)
 * - Simple navigation between list/edit/new
 * - Confirmation dialogs for destructive actions (delete)
 *
 * CSS: Minimal styling for forms and layout (<100 lines)
 */
interface CMSRenderer {
    /**
     * Renders article list page for CMS.
     * Shows all articles with edit/delete buttons.
     * @param articles List of all articles (published + drafts)
     * @return Complete HTML document
     */
    String renderArticleList(List<Article> articles);

    /**
     * Renders article editor form.
     * @param article Existing article to edit, or null for new article
     * @param csrfToken CSRF token for form submission
     * @return Complete HTML document with form
     */
    String renderEditor(Article article, String csrfToken);

    /**
     * Renders login page for CMS authentication.
     * @return Complete HTML document with login form
     */
    String renderLoginPage();

    /**
     * Renders preview of article content.
     * Same rendering as public article but with draft indicator.
     * @param article Article to preview
     * @return HTML fragment (not full document, for embedding in editor)
     */
    String renderPreview(Article article);
}

/**
 * Validates article data before saving.
 *
 * Ensures data integrity and security.
 *
 * Validation Rules:
 * - Title: 1-200 chars, not empty, no HTML tags
 * - Slug: 1-100 chars, matches [a-z0-9-]+, unique
 * - Content: not empty, < 1MB, no script tags, basic HTML only
 * - Summary: 0-500 chars, plain text only
 * - Author: 1-100 chars, not empty, no HTML tags
 * - Tags: each tag 1-50 chars, [a-z0-9-]+, max 10 tags
 * - Dates: valid ISO-8601 format, publishedAt not in future
 *
 * Preconditions:
 * - Article must not be null
 *
 * Postconditions:
 * - Returns true if valid
 * - Returns false if invalid (use getValidationErrors() for details)
 */
interface ArticleValidator {
    /**
     * Validates article data.
     * @param article Article to validate (must not be null)
     * @return true if valid, false otherwise
     */
    boolean validate(Article article);

    /**
     * Gets validation error messages from last validation.
     * @return List of error messages (empty if valid)
     */
    List<String> getValidationErrors();
}

/**
 * Sanitizes user input to prevent XSS and injection attacks.
 *
 * Uses Java's built-in features where possible.
 * No external libraries needed.
 *
 * Sanitization Rules:
 * - Remove all <script> tags and content
 * - Remove event handlers (onclick, onerror, etc.)
 * - Remove javascript: protocol from links
 * - Allow basic HTML: p, br, strong, em, a, ul, ol, li, h1-h6, blockquote, code, pre
 * - Escape HTML entities in text fields (title, author, summary)
 *
 * Preconditions:
 * - Input must not be null (empty string is valid)
 *
 * Postconditions:
 * - Output is safe for HTML rendering
 * - No executable code in output
 */
interface HTMLSanitizer {
    /**
     * Sanitizes HTML content (for article body).
     * Allows safe HTML tags, removes dangerous elements.
     * @param html Raw HTML input (must not be null)
     * @return Sanitized HTML safe for rendering
     */
    String sanitizeHTML(String html);

    /**
     * Escapes HTML entities for plain text fields.
     * Converts < > & " ' to HTML entities.
     * @param text Plain text input (must not be null)
     * @return HTML-escaped text safe for rendering
     */
    String escapeHTML(String text);
}

/**
 * Authentication for CMS access.
 *
 * Simple session-based authentication with HTTP Basic Auth fallback.
 * Credentials stored in config file (plaintext for simplicity, mention security note).
 *
 * Config file format (config/cms-auth.properties):
 * cms.username=admin
 * cms.password=changeme
 *
 * Security Note:
 * - HTTPS recommended for production
 * - Change default credentials immediately
 * - პაროლი hashing should be added for production use
 *
 * Session Management:
 * - Session token stored in cookie
 * - Session expires after 24 hours of inactivity
 * - Logout clears session cookie
 *
 * Preconditions:
 * - Config file must exist and be readable
 * - Credentials must be non-empty
 *
 * Postconditions:
 * - Returns true if authenticated
 * - Failed auth attempts logged
 */
interface CMSAuthenticator {
    /**
     * Authenticates user credentials.
     * @param username მომხმარებლის სახელი to check
     * @param password პაროლი to check
     * @return true if credentials valid, false otherwise
     */
    boolean authenticate(String username, String password);

    /**
     * Validates existing session token.
     * @param sessionToken Token from cookie
     * @return true if session valid and not expired
     */
    boolean validateSession(String sessionToken);

    /**
     * Creates new session token after successful authentication.
     * @return New session token (UUID format)
     */
    String createSession();

    /**
     * Invalidates session token (logout).
     * @param sessionToken Token to invalidate
     */
    void invalidateSession(String sessionToken);
}

/**
 * Main HTTP server configuration and lifecycle.
 *
 * Uses com.sun.net.httpserver.HttpServer (built into Java).
 * No external server needed (Tomcat, Jetty, etc.).
 *
 * Server Configuration:
 * - Port: 8080 (configurable via config file)
 * - Host: 0.0.0.0 (bind to all interfaces)
 * - Backlog: 0 (system default)
 * - Executor: Fixed thread pool (10 threads)
 *
 * Routes:
 * - / -> ArticleHandler (homepage)
 * - /article/* -> ArticleHandler (article pages)
 * - /cms/* -> CMSHandler (CMS interface)
 * - /static/* -> Static file handler (CSS, images if needed)
 *
 * Config file (config/server.properties):
 * server.port=8080
 * server.host=0.0.0.0
 * storage.path=data/articles
 *
 * Preconditions:
 * - Port must be available (not in use)
 * - Storage directory must exist or be creatable
 * - Config file must exist
 *
 * Postconditions:
 * - Server starts and binds to port
 * - Shutdown hook registered for graceful shutdown
 * - Logs startup information
 */
interface ArticleServer {
    /**
     * Starts the HTTP server.
     * Blocks until server is stopped.
     * @throws IOException if server cannot start (port in use, etc.)
     */
    void start() throws IOException;

    /**
     * Stops the HTTP server gracefully.
     * Waits for active requests to complete (max 5 seconds).
     */
    void stop();

    /**
     * Checks if server is currently running.
     * @return true if server is running
     */
    boolean isRunning();
}

/**
 * Configuration loader for server settings.
 *
 * Loads settings from config/server.properties using Java's Properties class.
 * Provides type-safe access to configuration values with defaults.
 *
 * Default values:
 * - server.port: 8080
 * - server.host: 0.0.0.0
 * - storage.path: data/articles
 * - cms.username: admin
 * - cms.password: changeme (warn user to change)
 *
 * Preconditions:
 * - Config file should exist (creates with defaults if missing)
 *
 * Postconditions:
 * - Returns valid configuration
 * - Missing values use defaults
 */
interface ServerConfig {
    /**
     * Gets server port.
     * @return Port number (1024-65535)
     */
    int getPort();

    /**
     * Gets server host address.
     * @return Host address (e.g., "0.0.0.0", "localhost")
     */
    String getHost();

    /**
     * Gets article storage path.
     * @return Filesystem path for article storage
     */
    String getStoragePath();

    /**
     * Gets CMS username.
     * @return CMS username
     */
    String getCmsUsername();

    /**
     * Gets CMS password.
     * @return CMS password
     */
    String getCmsPassword();
}

/**
 * CSRF token generator and validator for CMS forms.
 *
 * Prevents Cross-Site Request Forgery attacks.
 * Tokens stored in memory (session-based).
 * Token expires after use (one-time tokens).
 *
 * Token Format: UUID (e.g., "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6")
 *
 * Preconditions:
 * - Session must be valid when generating token
 *
 * Postconditions:
 * - Token valid for 1 hour or until used
 * - Used tokens immediately invalidated
 */
interface CSRFTokenManager {
    /**
     * Generates new CSRF token for session.
     * @param sessionToken Session token
     * @return New CSRF token
     */
    String generateToken(String sessionToken);

    /**
     * Validates and consumes CSRF token.
     * Token is invalidated after validation.
     * @param sessionToken Session token
     * @param csrfToken CSRF token to validate
     * @return true if valid, false otherwise
     */
    boolean validateAndConsume(String sessionToken, String csrfToken);
}

// ============================================================================
// DOMAIN MODEL IMPLEMENTATION
// ============================================================================

class ArticleImpl implements Article {
    private final String id;
    private final String title;
    private final String slug;
    private final String content;
    private final String summary;
    private final String author;
    private final LocalDateTime publishedAt;
    private final LocalDateTime updatedAt;
    private final boolean published;
    private final List<String> tags;

    public ArticleImpl(String id, String title, String slug, String content,
                       String summary, String author, LocalDateTime publishedAt,
                       LocalDateTime updatedAt, boolean published, List<String> tags) {
        this.id = id;
        this.title = title;
        this.slug = slug;
        this.content = content;
        this.summary = summary;
        this.author = author;
        this.publishedAt = publishedAt;
        this.updatedAt = updatedAt;
        this.published = published;
        this.tags = tags != null ? new ArrayList<>(tags) : new ArrayList<>();
    }

    @Override public String getId() { return id; }
    @Override public String getTitle() { return title; }
    @Override public String getSlug() { return slug; }
    @Override public String getContent() { return content; }
    @Override public String getSummary() { return summary; }
    @Override public String getAuthor() { return author; }
    @Override public LocalDateTime getPublishedAt() { return publishedAt; }
    @Override public LocalDateTime getUpdatedAt() { return updatedAt; }
    @Override public boolean isPublished() { return published; }
    @Override public List<String> getTags() { return new ArrayList<>(tags); }
}

// ============================================================================
// REPOSITORY IMPLEMENTATION
// ============================================================================

class FileArticleRepository implements ArticleRepository {
    private final Path storagePath;
    private final Path archivePath;
    private final Path indexPath;
    private final Object lock = new Object();
    private static final Logger logger = Logger.getLogger(FileArticleRepository.class.getName());

    public FileArticleRepository(String storageDir) throws IOException {
        this.storagePath = Paths.get(storageDir);
        this.archivePath = Paths.get(storageDir, "../archive");
        this.indexPath = storagePath.resolve("articles-index.json");

        Files.createDirectories(storagePath);
        Files.createDirectories(archivePath);

        if (!Files.exists(indexPath)) {
            Files.writeString(indexPath, "[]", StandardCharsets.UTF_8);
            logger.log(Level.INFO, "Created new index file at: {0}", indexPath);
        }

        logger.log(Level.INFO, "Initialized FileArticleRepository with storage path: {0}", storagePath);
    }

    @Override
    public void save(Article article) throws IOException {
        synchronized (lock) {
            Path articleFile = storagePath.resolve(article.getSlug() + ".json");
            String json = articleToJson(article);
            Files.writeString(articleFile, json, StandardCharsets.UTF_8);
            updateIndex();
            logger.log(Level.INFO, "Saved article: {0} ({1})", new Object[]{article.getSlug(), article.getTitle()});
        }
    }

    @Override
    public Optional<Article> findBySlug(String slug) throws IOException {
        Path articleFile = storagePath.resolve(slug + ".json");
        if (!Files.exists(articleFile)) {
            logger.log(Level.FINE, "Article not found by slug: {0}", slug);
            return Optional.empty();
        }
        String json = Files.readString(articleFile, StandardCharsets.UTF_8);
        Article article = jsonToArticle(json);
        logger.log(Level.FINE, "Found article by slug: {0}", slug);
        return Optional.of(article);
    }

    @Override
    public List<Article> findAllPublished() throws IOException {
        List<Article> articles = findAll().stream()
                .filter(Article::isPublished)
                .sorted((a, b) -> b.getPublishedAt().compareTo(a.getPublishedAt()))
                .collect(Collectors.toList());
        logger.log(Level.FINE, "Found {0} published articles", articles.size());
        return articles;
    }

    @Override
    public List<Article> findAll() throws IOException {
        List<Article> articles = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(storagePath, "*.json")) {
            for (Path path : stream) {
                if (path.getFileName().toString().equals("articles-index.json")) continue;
                String json = Files.readString(path, StandardCharsets.UTF_8);
                articles.add(jsonToArticle(json));
            }
        }
        articles.sort((a, b) -> {
            LocalDateTime aTime = a.getUpdatedAt() != null ? a.getUpdatedAt() : a.getPublishedAt();
            LocalDateTime bTime = b.getUpdatedAt() != null ? b.getUpdatedAt() : b.getPublishedAt();
            return bTime.compareTo(aTime);
        });
        logger.log(Level.FINE, "Found {0} total articles", articles.size());
        return articles;
    }

    @Override
    public boolean delete(String slug) throws IOException {
        synchronized (lock) {
            Path articleFile = storagePath.resolve(slug + ".json");
            if (!Files.exists(articleFile)) {
                logger.log(Level.WARNING, "Attempted to delete non-existent article: {0}", slug);
                return false;
            }
            Path archiveFile = archivePath.resolve(slug + ".json");
            Files.move(articleFile, archiveFile, StandardCopyOption.REPLACE_EXISTING);
            updateIndex();
            logger.log(Level.INFO, "Deleted article (moved to archive): {0}", slug);
            return true;
        }
    }

    private void updateIndex() throws IOException {
        List<Article> articles = findAll();
        StringBuilder json = new StringBuilder("[\n");
        for (int i = 0; i < articles.size(); i++) {
            Article a = articles.get(i);
            json.append("  {\"slug\":\"").append(a.getSlug())
                    .append("\",\"title\":\"").append(escapeJson(a.getTitle()))
                    .append("\",\"published\":").append(a.isPublished()).append("}");
            if (i < articles.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("]");
        Files.writeString(indexPath, json.toString(), StandardCharsets.UTF_8);
        logger.log(Level.FINEST, "Updated article index with {0} articles", articles.size());
    }

    private String articleToJson(Article a) {
        DateTimeFormatter fmt = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        StringBuilder json = new StringBuilder("{\n");
        json.append("  \"id\":\"").append(a.getId()).append("\",\n");
        json.append("  \"title\":\"").append(escapeJson(a.getTitle())).append("\",\n");
        json.append("  \"slug\":\"").append(a.getSlug()).append("\",\n");
        json.append("  \"content\":\"").append(escapeJson(a.getContent())).append("\",\n");
        json.append("  \"summary\":\"").append(escapeJson(a.getSummary())).append("\",\n");
        json.append("  \"author\":\"").append(escapeJson(a.getAuthor())).append("\",\n");
        json.append("  \"publishedAt\":\"").append(a.getPublishedAt().format(fmt)).append("\",\n");
        json.append("  \"updatedAt\":\"").append(a.getUpdatedAt() != null ? a.getUpdatedAt().format(fmt) : "").append("\",\n");
        json.append("  \"published\":").append(a.isPublished()).append(",\n");
        json.append("  \"tags\":[");
        List<String> tags = a.getTags();
        for (int i = 0; i < tags.size(); i++) {
            json.append("\"").append(escapeJson(tags.get(i))).append("\"");
            if (i < tags.size() - 1) json.append(",");
        }
        json.append("]\n}");
        return json.toString();
    }

    private Article jsonToArticle(String json) {
        // Simple JSON parser (no external libraries)
        String id = extractJsonString(json, "id");
        String title = extractJsonString(json, "title");
        String slug = extractJsonString(json, "slug");
        String content = extractJsonString(json, "content");
        String summary = extractJsonString(json, "summary");
        String author = extractJsonString(json, "author");
        String publishedAtStr = extractJsonString(json, "publishedAt");
        String updatedAtStr = extractJsonString(json, "updatedAt");
        boolean published = extractJsonBoolean(json, "published");
        List<String> tags = extractJsonArray(json, "tags");

        DateTimeFormatter fmt = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
        LocalDateTime publishedAt = LocalDateTime.parse(publishedAtStr, fmt);
        LocalDateTime updatedAt = updatedAtStr.isEmpty() ? null : LocalDateTime.parse(updatedAtStr, fmt);

        return new ArticleImpl(id, title, slug, content, summary, author,
                publishedAt, updatedAt, published, tags);
    }

    private String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\"";
        int keyStart = json.indexOf(pattern);
        if (keyStart == -1) return "";

        // Find the colon after the key
        int colonPos = json.indexOf(":", keyStart);
        if (colonPos == -1) return "";

        // Find the opening quote
        int quoteStart = json.indexOf("\"", colonPos);
        if (quoteStart == -1) return "";

        // Find the closing quote, handling escaped quotes
        int quoteEnd = quoteStart + 1;
        while (quoteEnd < json.length()) {
            char c = json.charAt(quoteEnd);
            if (c == '"' && json.charAt(quoteEnd - 1) != '\\') {
                break;
            }
            quoteEnd++;
        }

        if (quoteEnd >= json.length()) return "";

        return unescapeJson(json.substring(quoteStart + 1, quoteEnd));
    }

    private boolean extractJsonBoolean(String json, String key) {
        String pattern = "\"" + key + "\"";
        int keyStart = json.indexOf(pattern);
        if (keyStart == -1) return false;

        // Find the colon after the key
        int colonPos = json.indexOf(":", keyStart);
        if (colonPos == -1) return false;

        // Skip whitespace after colon
        int valueStart = colonPos + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }

        // Check if the value starts with 'true'
        return json.substring(valueStart).startsWith("true");
    }

    private List<String> extractJsonArray(String json, String key) {
        List<String> result = new ArrayList<>();
        String pattern = "\"" + key + "\"";
        int keyStart = json.indexOf(pattern);
        if (keyStart == -1) return result;

        // Find the opening bracket
        int bracketStart = json.indexOf("[", keyStart);
        if (bracketStart == -1) return result;

        // Find the closing bracket
        int bracketEnd = json.indexOf("]", bracketStart);
        if (bracketEnd == -1) return result;

        String arrayContent = json.substring(bracketStart + 1, bracketEnd).trim();
        if (arrayContent.isEmpty()) return result;

        // Parse array items
        int pos = 0;
        while (pos < arrayContent.length()) {
            // Skip whitespace and commas
            while (pos < arrayContent.length() &&
                    (Character.isWhitespace(arrayContent.charAt(pos)) || arrayContent.charAt(pos) == ',')) {
                pos++;
            }

            if (pos >= arrayContent.length()) break;

            // Find string start
            if (arrayContent.charAt(pos) == '"') {
                int stringStart = pos + 1;
                int stringEnd = stringStart;

                // Find string end, handling escaped quotes
                while (stringEnd < arrayContent.length()) {
                    char c = arrayContent.charAt(stringEnd);
                    if (c == '"' && (stringEnd == stringStart || arrayContent.charAt(stringEnd - 1) != '\\')) {
                        break;
                    }
                    stringEnd++;
                }

                if (stringEnd < arrayContent.length()) {
                    result.add(unescapeJson(arrayContent.substring(stringStart, stringEnd)));
                    pos = stringEnd + 1;
                } else {
                    break;
                }
            } else {
                pos++;
            }
        }

        return result;
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String unescapeJson(String s) {
        return s.replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\\", "\\");
    }
}

// ============================================================================
// HTML SANITIZER IMPLEMENTATION
// ============================================================================

class SimpleHTMLSanitizer implements HTMLSanitizer {
    private static final Set<String> ALLOWED_TAGS = new HashSet<>(Arrays.asList(
            "p", "br", "strong", "em", "b", "i", "a", "ul", "ol", "li",
            "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "code", "pre"
    ));
    private static final Logger logger = Logger.getLogger(SimpleHTMLSanitizer.class.getName());

    @Override
    public String sanitizeHTML(String html) {
        if (html == null) return "";

        // Remove script tags and content
        String original = html;
        html = html.replaceAll("(?i)<script[^>]*>.*?</script>", "");
        if (!original.equals(html)) {
            logger.log(Level.WARNING, "Removed script tags from HTML content");
        }

        // Remove event handlers
        html = html.replaceAll("(?i)\\s*on\\w+\\s*=\\s*[\"'][^\"']*[\"']", "");
        html = html.replaceAll("(?i)\\s*on\\w+\\s*=\\s*[^\\s>]*", "");

        // Remove javascript: protocol
        html = html.replaceAll("(?i)javascript:", "");

        // Basic tag validation (remove non-allowed tags)
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < html.length()) {
            if (html.charAt(i) == '<') {
                int end = html.indexOf('>', i);
                if (end == -1) break;
                String tag = html.substring(i + 1, end);
                String tagName = tag.split("\\s")[0].replaceAll("/", "").toLowerCase();

                if (ALLOWED_TAGS.contains(tagName) || tag.startsWith("/")) {
                    result.append(html, i, end + 1);
                } else {
                    logger.log(Level.FINE, "Removed disallowed HTML tag: {0}", tagName);
                }
                i = end + 1;
            } else {
                result.append(html.charAt(i));
                i++;
            }
        }

        return result.toString();
    }

    @Override
    public String escapeHTML(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}

// ============================================================================
// ARTICLE VALIDATOR IMPLEMENTATION
// ============================================================================

class SimpleArticleValidator implements ArticleValidator {
    private final List<String> errors = new ArrayList<>();
    private static final Pattern SLUG_PATTERN = Pattern.compile("^[a-z0-9-]+$");
    private static final Logger logger = Logger.getLogger(SimpleArticleValidator.class.getName());

    @Override
    public boolean validate(Article article) {
        errors.clear();

        if (article == null) {
            errors.add("Article cannot be null");
            logger.log(Level.WARNING, "Validation failed: article is null");
            return false;
        }

        // Title validation
        if (article.getTitle() == null || article.getTitle().trim().isEmpty()) {
            errors.add("Title is required");
        } else if (article.getTitle().length() > 200) {
            errors.add("Title must be 200 characters or less");
        }

        // Slug validation
        if (article.getSlug() == null || article.getSlug().trim().isEmpty()) {
            errors.add("Slug is required");
        } else if (article.getSlug().length() > 100) {
            errors.add("Slug must be 100 characters or less");
        } else if (!SLUG_PATTERN.matcher(article.getSlug()).matches()) {
            errors.add("Slug must contain only lowercase letters, numbers, and hyphens");
        }

        // Content validation
        if (article.getContent() == null || article.getContent().trim().isEmpty()) {
            errors.add("Content is required");
        } else if (article.getContent().length() > 1048576) { // 1MB
            errors.add("Content must be less than 1MB");
        }

        // Summary validation
        if (article.getSummary() != null && article.getSummary().length() > 500) {
            errors.add("Summary must be 500 characters or less");
        }

        // Author validation
        if (article.getAuthor() == null || article.getAuthor().trim().isEmpty()) {
            errors.add("Author is required");
        } else if (article.getAuthor().length() > 100) {
            errors.add("Author must be 100 characters or less");
        }

        // Tags validation
        List<String> tags = article.getTags();
        if (tags != null) {
            if (tags.size() > 10) {
                errors.add("Maximum 10 tags allowed");
            }
            for (String tag : tags) {
                if (tag.length() > 50) {
                    errors.add("Tag '" + tag + "' exceeds 50 characters");
                }
            }
        }

        // Date validation
        if (article.getPublishedAt() == null) {
            errors.add("Published date is required");
        } else if (article.getPublishedAt().isAfter(LocalDateTime.now())) {
            errors.add("Published date cannot be in the future");
        }

        boolean isValid = errors.isEmpty();
        if (!isValid) {
            logger.log(Level.WARNING, "Article validation failed with {0} errors: {1}",
                    new Object[]{errors.size(), String.join(", ", errors)});
        } else {
            logger.log(Level.FINE, "Article validation passed for: {0}", article.getTitle());
        }

        return isValid;
    }

    @Override
    public List<String> getValidationErrors() {
        return new ArrayList<>(errors);
    }
}

// ============================================================================
// ARTICLE RENDERER IMPLEMENTATION
// ============================================================================

class SimpleArticleRenderer implements ArticleRenderer {
    private final HTMLSanitizer sanitizer;
    private static final Logger logger = Logger.getLogger(SimpleArticleRenderer.class.getName());

    public SimpleArticleRenderer(HTMLSanitizer sanitizer) {
        this.sanitizer = sanitizer;
    }

    @Override
    public String renderArticlePage(Article article) {
        if (article == null) {
            logger.log(Level.WARNING, "Attempted to render null article");
            throw new IllegalArgumentException("Article cannot be null");
        }
        if (!article.isPublished()) {
            logger.log(Level.WARNING, "Attempted to render unpublished article: {0}", article.getSlug());
            throw new IllegalArgumentException("Article must be published");
        }

        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("MMMM d, yyyy");
        String date = article.getPublishedAt().format(fmt);

        logger.log(Level.FINE, "Rendering article page: {0}", article.getSlug());
        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" +
                "<meta charset=\"UTF-8\">\n" +
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "<meta name=\"description\" content=\"" + sanitizer.escapeHTML(article.getSummary()) + "\">\n" +
                "<meta name=\"author\" content=\"" + sanitizer.escapeHTML(article.getAuthor()) + "\">\n" +
                "<title>" + sanitizer.escapeHTML(article.getTitle()) + "</title>\n" +
                "<style>" + getCSS() + "</style>\n" +
                "</head>\n<body>\n" +
                "<header><nav><a href=\"/\">← Home</a></nav></header>\n" +
                "<main>\n" +
                "<article>\n" +
                "<h1>" + sanitizer.escapeHTML(article.getTitle()) + "</h1>\n" +
                "<p class=\"meta\">By " + sanitizer.escapeHTML(article.getAuthor()) + " on " + date + "</p>\n" +
                (article.getTags().isEmpty() ? "" : "<p class=\"tags\">Tags: " +
                        String.join(", ", article.getTags().stream().map(sanitizer::escapeHTML).collect(Collectors.toList())) + "</p>\n") +
                "<div class=\"content\">\n" + article.getContent() + "\n</div>\n" +
                "</article>\n" +
                "</main>\n" +
                "<footer><p>© 2025 ქართული ახალი ამბები</p></footer>\n" +
                "</body>\n</html>";
    }

    @Override
    public String renderHomePage(List<Article> articles) {
        logger.log(Level.FINE, "Rendering homepage with {0} articles", articles.size());

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
                .append("<meta charset=\"UTF-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
                .append("<title>ქართული ახალი ამბები</title>\n")
                .append("<style>").append(getCSS()).append("</style>\n")
                .append("</head>\n<body>\n")
                .append("<header><h1>ქართული ახალი ამბები</h1></header>\n")
                .append("<main>\n");

        if (articles.isEmpty()) {
            html.append("<p>ახალი ამბები არ მოიძებნა.</p>\n");
            logger.log(Level.INFO, "Rendered homepage with no articles");
        } else {
            for (Article article : articles) {
                DateTimeFormatter fmt = DateTimeFormatter.ofPattern("MMMM d, yyyy");
                String date = article.getPublishedAt().format(fmt);

                html.append("<article class=\"preview\">\n")
                        .append("<h2><a href=\"/article/").append(article.getSlug()).append("\">")
                        .append(sanitizer.escapeHTML(article.getTitle())).append("</a></h2>\n")
                        .append("<p class=\"meta\">By ").append(sanitizer.escapeHTML(article.getAuthor()))
                        .append(" on ").append(date).append("</p>\n");

                if (article.getSummary() != null && !article.getSummary().isEmpty()) {
                    html.append("<p>").append(sanitizer.escapeHTML(article.getSummary())).append("</p>\n");
                }

                html.append("<p><a href=\"/article/").append(article.getSlug()).append("\">Read more →</a></p>\n")
                        .append("</article>\n");
            }
            logger.log(Level.FINE, "Rendered homepage with {0} articles", articles.size());
        }

        html.append("</main>\n")
                .append("<footer><p>© 2025 ქართული ახალი ამბები | <a href=\"/cms\">CMS-ში შესვლა</a></p></footer>\n")
                .append("</body>\n</html>");

        return html.toString();
    }

    @Override
    public String render404Page() {
        logger.log(Level.FINE, "Rendering 404 page");
        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" +
                "<meta charset=\"UTF-8\">\n" +
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "<title>404 - Not Found</title>\n" +
                "<style>" + getCSS() + "</style>\n" +
                "</head>\n<body>\n" +
                "<header><nav><a href=\"/\">← Home</a></nav></header>\n" +
                "<main>\n" +
                "<h1>404 - Page Not Found</h1>\n" +
                "<p>The article you're looking for doesn't exist.</p>\n" +
                "</main>\n" +
                "<footer><p>© 2025 ქართული ახალი ამბები</p></footer>\n" +
                "</body>\n</html>";
    }

    @Override
    public String renderErrorPage(String message) {
        logger.log(Level.WARNING, "Rendering error page with message: {0}", message);
        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" +
                "<meta charset=\"UTF-8\">\n" +
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "<title>Error</title>\n" +
                "<style>" + getCSS() + "</style>\n" +
                "</head>\n<body>\n" +
                "<header><nav><a href=\"/\">← Home</a></nav></header>\n" +
                "<main>\n" +
                "<h1>Error</h1>\n" +
                "<p>" + sanitizer.escapeHTML(message) + "</p>\n" +
                "</main>\n" +
                "<footer><p>© 2025 ქართული ახალი ამბები</p></footer>\n" +
                "</body>\n</html>";
    }

    private String getCSS() {
        return "body{font-family:Georgia,serif;line-height:1.6;max-width:800px;margin:0 auto;padding:20px;color:#000;background:#fff}" +
                "header,footer{text-align:center;padding:20px 0;border-bottom:1px solid #ccc}" +
                "footer{border-top:1px solid #ccc;border-bottom:none}" +
                "a{color:#00e;text-decoration:underline}" +
                "a:visited{color:#551a8b}" +
                "h1{font-size:2em;margin:20px 0}" +
                "h2{font-size:1.5em;margin:15px 0}" +
                ".meta{color:#666;font-size:0.9em;margin:5px 0}" +
                ".tags{color:#666;font-size:0.9em;font-style:italic}" +
                ".content{margin:30px 0}" +
                ".preview{margin:30px 0;padding-bottom:30px;border-bottom:1px solid #eee}" +
                "code{font-family:monospace;background:#f4f4f4;padding:2px 5px}" +
                "pre{background:#f4f4f4;padding:10px;overflow-x:auto}" +
                "blockquote{border-left:3px solid #ccc;margin:20px 0;padding-left:20px;color:#666}" +
                "@media(max-width:600px){body{padding:10px;font-size:14px}}";
    }
}

// ============================================================================
// CMS RENDERER IMPLEMENTATION
// ============================================================================

class SimpleCMSRenderer implements CMSRenderer {
    private final HTMLSanitizer sanitizer;
    private static final Logger logger = Logger.getLogger(SimpleCMSRenderer.class.getName());

    public SimpleCMSRenderer(HTMLSanitizer sanitizer) {
        this.sanitizer = sanitizer;
    }

    @Override
    public String renderArticleList(List<Article> articles) {
        logger.log(Level.FINE, "Rendering CMS article list with {0} articles", articles.size());

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
                .append("<meta charset=\"UTF-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
                .append("<title>CMS - Article List</title>\n")
                .append("<style>").append(getCMSCSS()).append("</style>\n")
                .append("</head>\n<body>\n")
                .append("<header><h1>CMS - Articles</h1>")
                .append("<nav><a href=\"/cms/new\">New Article</a> | <a href=\"/cms/logout\">Logout</a> | <a href=\"/\">View Site</a></nav>")
                .append("</header>\n<main>\n");

        if (articles.isEmpty()) {
            html.append("<p>ახალი ამბები არ მოიძებნა. <a href=\"/cms/new\">Create one</a>.</p>\n");
        } else {
            html.append("<table>\n<thead><tr><th>Title</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead>\n<tbody>\n");
            DateTimeFormatter fmt = DateTimeFormatter.ofPattern("MMM d, yyyy");

            for (Article article : articles) {
                String date = article.getPublishedAt().format(fmt);
                String status = article.isPublished() ? "Published" : "Draft";

                html.append("<tr>")
                        .append("<td><a href=\"/cms/edit/").append(article.getSlug()).append("\">")
                        .append(sanitizer.escapeHTML(article.getTitle())).append("</a></td>")
                        .append("<td>").append(status).append("</td>")
                        .append("<td>").append(date).append("</td>")
                        .append("<td>")
                        .append("<a href=\"/cms/edit/").append(article.getSlug()).append("\">Edit</a> | ")
                        .append("<a href=\"/article/").append(article.getSlug()).append("\" target=\"_blank\">View</a> | ")
                        .append("<a href=\"/cms/delete/").append(article.getSlug()).append("\" onclick=\"return confirm('Delete this article?')\">Delete</a>")
                        .append("</td>")
                        .append("</tr>\n");
            }

            html.append("</tbody>\n</table>\n");
        }

        html.append("</main>\n</body>\n</html>");
        return html.toString();
    }

    @Override
    public String renderEditor(Article article, String csrfToken) {
        boolean isNew = article == null;
        String id = isNew ? UUID.randomUUID().toString() : article.getId();
        String title = isNew ? "" : sanitizer.escapeHTML(article.getTitle());
        String slug = isNew ? "" : sanitizer.escapeHTML(article.getSlug());
        String content = isNew ? "" : sanitizer.escapeHTML(article.getContent());
        String summary = isNew ? "" : sanitizer.escapeHTML(article.getSummary());
        String author = isNew ? "" : sanitizer.escapeHTML(article.getAuthor());
        String tags = isNew ? "" : String.join(", ", article.getTags());
        boolean published = !isNew && article.isPublished();

        logger.log(Level.FINE, "Rendering CMS editor for article: {0}", isNew ? "new" : article.getSlug());

        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" +
                "<meta charset=\"UTF-8\">\n" +
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "<title>CMS - " + (isNew ? "New Article" : "Edit Article") + "</title>\n" +
                "<style>" + getCMSCSS() + "</style>\n" +
                "</head>\n<body>\n" +
                "<header><h1>" + (isNew ? "New Article" : "Edit Article") + "</h1>" +
                "<nav><a href=\"/cms\">← Back to List</a> | <a href=\"/cms/logout\">Logout</a></nav>" +
                "</header>\n<main>\n" +
                "<form method=\"POST\" action=\"/cms/save\">\n" +
                "<input type=\"hidden\" name=\"id\" value=\"" + id + "\">\n" +
                "<input type=\"hidden\" name=\"csrf\" value=\"" + csrfToken + "\">\n" +
                "<div class=\"form-group\">" +
                "<label for=\"title\">Title <span class=\"counter\" id=\"title-counter\">0/200</span></label>" +
                "<input type=\"text\" id=\"title\" name=\"title\" value=\"" + title + "\" required maxlength=\"200\">" +
                "</div>\n" +
                "<div class=\"form-group\">" +
                "<label for=\"slug\">Slug (URL-friendly, lowercase, hyphens only)</label>" +
                "<input type=\"text\" id=\"slug\" name=\"slug\" value=\"" + slug + "\" required maxlength=\"100\" pattern=\"[a-z0-9-]+\">" +
                "</div>\n" +
                "<div class=\"form-group\">" +
                "<label for=\"author\">Author</label>" +
                "<input type=\"text\" id=\"author\" name=\"author\" value=\"" + author + "\" required maxlength=\"100\">" +
                "</div>\n" +
                "<div class=\"form-group\">" +
                "<label for=\"summary\">Summary <span class=\"counter\" id=\"summary-counter\">0/500</span></label>" +
                "<textarea id=\"summary\" name=\"summary\" rows=\"3\" maxlength=\"500\">" + summary + "</textarea>" +
                "</div>\n" +
                "<div class=\"form-group\">" +
                "<label for=\"content\">Content (HTML allowed)</label>" +
                "<textarea id=\"content\" name=\"content\" rows=\"20\" required>" + content + "</textarea>" +
                "</div>\n" +
                "<div class=\"form-group\">" +
                "<label for=\"tags\">Tags (comma-separated, lowercase)</label>" +
                "<input type=\"text\" id=\"tags\" name=\"tags\" value=\"" + tags + "\">" +
                "</div>\n" +
                "<div class=\"form-group\">" +
                "<label><input type=\"checkbox\" name=\"published\" value=\"true\"" + (published ? " checked" : "") + "> Published</label>" +
                "</div>\n" +
                "<div class=\"form-actions\">" +
                "<button type=\"submit\">Save Article</button>" +
                "<a href=\"/cms\" class=\"btn-cancel\">Cancel</a>" +
                "</div>\n" +
                "</form>\n" +
                "</main>\n" +
                "<script>" +
                "document.getElementById('title').addEventListener('input',function(){" +
                "document.getElementById('title-counter').textContent=this.value.length+'/200';" +
                "if(!document.getElementById('slug').value){" +
                "document.getElementById('slug').value=this.value.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');" +
                "}});" +
                "document.getElementById('summary').addEventListener('input',function(){" +
                "document.getElementById('summary-counter').textContent=this.value.length+'/500';" +
                "});" +
                "</script>" +
                "</body>\n</html>";
    }


    @Override
    public String renderLoginPage() {
        logger.log(Level.FINE, "Rendering CMS login page");
        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" +
                "<meta charset=\"UTF-8\">\n" +
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
                "<title>CMS-ში შესვლა</title>\n" +
                "<style>" + getCMSCSS() + "</style>\n" +
                "</head>\n<body>\n" +
                "<header><h1>CMS-ში შესვლა</h1></header>\n" +
                "<main>\n" +
                "<form method=\"POST\" action=\"/cms/login\" class=\"login-form\">\n" +
                "<div class=\"form-group\">" +
                "<label for=\"username\">მომხმარებლის სახელი</label>" +
                "<input type=\"text\" id=\"username\" name=\"username\" required autofocus>" +
                "</div>\n" +
                "<div class=\"form-group\">" +
                "<label for=\"password\">პაროლი</label>" +
                "<input type=\"password\" id=\"password\" name=\"password\" required>" +
                "</div>\n" +
                "<div class=\"form-actions\">" +
                "<button type=\"submit\">Login</button>" +
                "</div>\n" +
                "</form>\n" +
                "<p style=\"text-align:center;margin-top:30px;\"><a href=\"/\">← საიტზე დაბრუნება</a></p>\n" +
                "</main>\n" +
                "</body>\n</html>";
    }

    @Override
    public String renderPreview(Article article) {
        if (article == null) {
            logger.log(Level.FINE, "Rendering empty preview");
            return "<div class=\"preview-empty\"><p>No content to preview</p></div>";
        }

        logger.log(Level.FINE, "Rendering preview for article: {0}", article.getSlug());

        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("MMMM d, yyyy");
        String date = article.getPublishedAt().format(fmt);

        StringBuilder html = new StringBuilder();
        html.append("<div class=\"preview-content\">\n");

        if (!article.isPublished()) {
            html.append("<div class=\"draft-indicator\">DRAFT - Not Published</div>\n");
        }

        html.append("<article>\n")
                .append("<h1>").append(sanitizer.escapeHTML(article.getTitle())).append("</h1>\n")
                .append("<p class=\"meta\">By ").append(sanitizer.escapeHTML(article.getAuthor()))
                .append(" on ").append(date).append("</p>\n");

        if (!article.getTags().isEmpty()) {
            html.append("<p class=\"tags\">Tags: ")
                    .append(article.getTags().stream()
                            .map(sanitizer::escapeHTML)
                            .collect(Collectors.joining(", ")))
                    .append("</p>\n");
        }

        html.append("<div class=\"content\">\n")
                .append(article.getContent())
                .append("\n</div>\n")
                .append("</article>\n")
                .append("</div>");

        return html.toString();
    }

    private String getCMSCSS() {
        return "body{font-family:Arial,sans-serif;line-height:1.6;max-width:1200px;margin:0 auto;padding:20px;color:#333;background:#f5f5f5}" +
                "header{background:#fff;padding:20px;margin-bottom:30px;border-bottom:2px solid #333}" +
                "header h1{margin:0 0 10px 0;font-size:1.8em}" +
                "header nav{font-size:0.9em}" +
                "header nav a{margin-right:15px;color:#00e;text-decoration:none}" +
                "header nav a:hover{text-decoration:underline}" +
                "main{background:#fff;padding:30px;border-radius:5px;box-shadow:0 2px 5px rgba(0,0,0,0.1)}" +
                "table{width:100%;border-collapse:collapse;margin:20px 0}" +
                "table th,table td{padding:12px;text-align:left;border-bottom:1px solid #ddd}" +
                "table th{background:#f0f0f0;font-weight:bold}" +
                "table tr:hover{background:#f9f9f9}" +
                "table a{color:#00e;text-decoration:none}" +
                "table a:hover{text-decoration:underline}" +
                ".form-group{margin-bottom:20px}" +
                ".form-group label{display:block;margin-bottom:5px;font-weight:bold}" +
                ".form-group input[type=text],.form-group input[type=password],.form-group textarea{width:100%;padding:10px;border:1px solid #ccc;border-radius:3px;font-size:1em;font-family:inherit}" +
                ".form-group textarea{font-family:monospace;resize:vertical}" +
                ".form-group input[type=checkbox]{margin-right:8px}" +
                ".counter{float:right;color:#999;font-weight:normal;font-size:0.9em}" +
                ".form-actions{margin-top:30px;padding-top:20px;border-top:1px solid #eee}" +
                ".form-actions button{background:#333;color:#fff;padding:12px 30px;border:none;border-radius:3px;font-size:1em;cursor:pointer;margin-right:10px}" +
                ".form-actions button:hover{background:#555}" +
                ".btn-cancel{padding:12px 30px;color:#333;text-decoration:none;border:1px solid #ccc;border-radius:3px;display:inline-block}" +
                ".btn-cancel:hover{background:#f0f0f0}" +
                ".login-form{max-width:400px;margin:50px auto}" +
                ".draft-indicator{background:#ff9;padding:10px;margin-bottom:20px;border:2px solid #cc6;border-radius:3px;text-align:center;font-weight:bold}" +
                ".preview-content{padding:20px}" +
                ".preview-content .content{margin-top:30px;border-top:1px solid #eee;padding-top:20px}" +
                ".preview-empty{text-align:center;color:#999;padding:50px}" +
                ".meta{color:#666;font-size:0.9em;margin:5px 0}" +
                ".tags{color:#666;font-size:0.9em;font-style:italic;margin:10px 0}" +
                ".content{line-height:1.8}" +
                ".content h1,.content h2,.content h3{margin-top:25px;margin-bottom:15px}" +
                ".content p{margin:15px 0}" +
                ".content code{background:#f4f4f4;padding:2px 6px;border-radius:3px;font-family:monospace}" +
                ".content pre{background:#f4f4f4;padding:15px;border-radius:3px;overflow-x:auto}" +
                ".content blockquote{border-left:4px solid #ccc;margin:20px 0;padding-left:20px;color:#666}" +
                ".content ul,.content ol{margin:15px 0;padding-left:30px}" +
                ".content a{color:#00e;text-decoration:underline}" +
                "@media(max-width:768px){body{padding:10px}main{padding:15px}.form-group input,.form-group textarea{font-size:16px}table{font-size:0.9em}table th,table td{padding:8px}}";
    }
}


// ============================================================================
// SERVER CONFIG IMPLEMENTATION
// ============================================================================

class SimpleServerConfig implements ServerConfig {
    private final Properties props;
    private static final Logger logger = Logger.getLogger(SimpleServerConfig.class.getName());

    public SimpleServerConfig() {
        props = new Properties();

        // Load with defaults, then override from system properties
        props.setProperty("server.port", System.getProperty("server.port", "8080"));
        props.setProperty("server.host", System.getProperty("server.host", "0.0.0.0"));
        props.setProperty("storage.path", System.getProperty("storage.path", "data/articles"));
        props.setProperty("cms.username", System.getProperty("cms.username", "admin"));
        props.setProperty("cms.password", System.getProperty("cms.password", "changeme"));

        logger.log(Level.INFO, "Configuration initialized");
    }

    @Override
    public int getPort() {
        return Integer.parseInt(props.getProperty("server.port", "8080"));
    }

    @Override
    public String getHost() {
        return props.getProperty("server.host", "0.0.0.0");
    }

    @Override
    public String getStoragePath() {
        return props.getProperty("storage.path", "data/articles");
    }

    @Override
    public String getCmsUsername() {
        return props.getProperty("cms.username", "admin");
    }

    @Override
    public String getCmsPassword() {
        return props.getProperty("cms.password", "changeme");
    }
}

// ============================================================================
// CSRF TOKEN MANAGER IMPLEMENTATION
// ============================================================================

class SimpleCSRFTokenManager implements CSRFTokenManager {
    private final Map<String, Map<String, Long>> sessionTokens = new ConcurrentHashMap<>();
    private static final long TOKEN_EXPIRY = 3600000; // 1 hour in milliseconds
    private static final Logger logger = Logger.getLogger(SimpleCSRFTokenManager.class.getName());

    @Override
    public String generateToken(String sessionToken) {
        String csrfToken = UUID.randomUUID().toString();
        sessionTokens.computeIfAbsent(sessionToken, k -> new ConcurrentHashMap<>())
                .put(csrfToken, System.currentTimeMillis());
        logger.log(Level.FINE, "Generated CSRF token for session: {0}", sessionToken);
        return csrfToken;
    }

    @Override
    public boolean validateAndConsume(String sessionToken, String csrfToken) {
        Map<String, Long> tokens = sessionTokens.get(sessionToken);
        if (tokens == null) {
            logger.log(Level.WARNING, "CSRF validation failed: no tokens for session");
            return false;
        }

        Long timestamp = tokens.remove(csrfToken);
        if (timestamp == null) {
            logger.log(Level.WARNING, "CSRF validation failed: token not found");
            return false;
        }

        boolean isValid = (System.currentTimeMillis() - timestamp) < TOKEN_EXPIRY;
        if (!isValid) {
            logger.log(Level.WARNING, "CSRF validation failed: token expired");
        } else {
            logger.log(Level.FINE, "CSRF token validated successfully");
        }

        return isValid;
    }

    public void cleanExpiredTokens() {
        long now = System.currentTimeMillis();
        int before = sessionTokens.values().stream().mapToInt(Map::size).sum();
        sessionTokens.values().forEach(tokens ->
                tokens.entrySet().removeIf(e -> (now - e.getValue()) > TOKEN_EXPIRY)
        );
        int after = sessionTokens.values().stream().mapToInt(Map::size).sum();

        if (before > after) {
            logger.log(Level.FINE, "Cleaned {0} expired CSRF tokens", before - after);
        }
    }
}

// ============================================================================
// CMS AUTHENTICATOR IMPLEMENTATION
// ============================================================================

class SimpleCMSAuthenticator implements CMSAuthenticator {
    private final String validUsername;
    private final String validPassword;
    private final Map<String, Long> sessions = new ConcurrentHashMap<>();
    private static final long SESSION_EXPIRY = 86400000; // 24 hours
    private static final Logger logger = Logger.getLogger(SimpleCMSAuthenticator.class.getName());

    public SimpleCMSAuthenticator(String username, String password) {
        this.validUsername = username;
        this.validPassword = password;
        logger.log(Level.INFO, "Initialized CMS authenticator for user: {0}", username);
    }

    @Override
    public boolean authenticate(String username, String password) {
        boolean isValid = validUsername.equals(username) && validPassword.equals(password);
        if (isValid) {
            logger.log(Level.INFO, "Successful authentication for user: {0}", username);
        } else {
            logger.log(Level.WARNING, "Failed authentication attempt for user: {0}", username);
        }
        return isValid;
    }

    @Override
    public boolean validateSession(String sessionToken) {
        Long timestamp = sessions.get(sessionToken);
        if (timestamp == null) {
            logger.log(Level.FINE, "Session validation failed: token not found");
            return false;
        }

        if (System.currentTimeMillis() - timestamp > SESSION_EXPIRY) {
            sessions.remove(sessionToken);
            logger.log(Level.FINE, "Session validation failed: token expired");
            return false;
        }

        // Refresh session
        sessions.put(sessionToken, System.currentTimeMillis());
        logger.log(Level.FINE, "Session validated successfully");
        return true;
    }

    @Override
    public String createSession() {
        String token = UUID.randomUUID().toString();
        sessions.put(token, System.currentTimeMillis());
        logger.log(Level.INFO, "Created new session token");
        return token;
    }

    @Override
    public void invalidateSession(String sessionToken) {
        sessions.remove(sessionToken);
        logger.log(Level.INFO, "Invalidated session token");
    }
}




// ============================================================================
// ARTICLE HANDLER IMPLEMENTATION
// ============================================================================

class SimpleArticleHandler implements ArticleHandler {
    private final ArticleRepository repository;
    private final ArticleRenderer renderer;
    private static final Logger logger = Logger.getLogger(SimpleArticleHandler.class.getName());

    public SimpleArticleHandler(ArticleRepository repository, ArticleRenderer renderer) {
        this.repository = repository;
        this.renderer = renderer;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        String clientIP = getClientIP(exchange);

        logger.log(Level.INFO, "Request: {0} {1} from {2}", new Object[]{method, path, clientIP});

        if (!method.equals("GET")) {
            logger.log(Level.WARNING, "Method not allowed: {0} for path {1}", new Object[]{method, path});
            sendResponse(exchange, 405, "Method Not Allowed");
            return;
        }

        try {
            if (path.equals("/")) {
                handleHomePage(exchange);
            } else if (path.startsWith("/article/")) {
                handleArticlePage(exchange, path.substring(9));
            } else {
                logger.log(Level.FINE, "404 Not Found: {0}", path);
                sendHtmlResponse(exchange, 404, renderer.render404Page());
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error handling request: " + path, e);
            sendHtmlResponse(exchange, 500, renderer.renderErrorPage("Internal server error"));
        }
    }

    private void handleHomePage(HttpExchange exchange) throws IOException {
        logger.log(Level.FINE, "Handling homepage request");
        List<Article> articles = repository.findAllPublished();
        String html = renderer.renderHomePage(articles);
        sendHtmlResponse(exchange, 200, html);
        logger.log(Level.FINE, "Homepage rendered with {0} articles", articles.size());
    }

    private void handleArticlePage(HttpExchange exchange, String slug) throws IOException {
        logger.log(Level.FINE, "Handling article page request for slug: {0}", slug);
        Optional<Article> article = repository.findBySlug(slug);

        if (article.isEmpty() || !article.get().isPublished()) {
            logger.log(Level.FINE, "Article not found or not published: {0}", slug);
            sendHtmlResponse(exchange, 404, renderer.render404Page());
            return;
        }

        String html = renderer.renderArticlePage(article.get());
        sendHtmlResponse(exchange, 200, html);
        logger.log(Level.FINE, "Article page rendered successfully: {0}", slug);
    }

    private String getClientIP(HttpExchange exchange) {
        String xForwardedFor = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    private void sendHtmlResponse(HttpExchange exchange, int statusCode, String html) throws IOException {
        byte[] response = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "public, max-age=3600");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(statusCode, response.length);
        exchange.getResponseBody().write(response);
        exchange.getResponseBody().close();
        logger.log(Level.FINE, "Sent HTML response with status: {0}", statusCode);
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        byte[] response = message.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, response.length);
        exchange.getResponseBody().write(response);
        exchange.getResponseBody().close();
        logger.log(Level.FINE, "Sent response with status: {0}", statusCode);
    }
}

// ============================================================================
// CMS HANDLER IMPLEMENTATION (Simplified)
// ============================================================================

class SimpleCMSHandler implements CMSHandler {
    private final ArticleRepository repository;
    private final CMSRenderer renderer;
    private final CMSAuthenticator authenticator;
    private final CSRFTokenManager csrfManager;
    private final ArticleValidator validator;
    private final HTMLSanitizer sanitizer;
    private static final Logger logger = Logger.getLogger(SimpleCMSHandler.class.getName());

    public SimpleCMSHandler(ArticleRepository repository, CMSRenderer renderer,
                            CMSAuthenticator authenticator, CSRFTokenManager csrfManager,
                            ArticleValidator validator, HTMLSanitizer sanitizer) {
        this.repository = repository;
        this.renderer = renderer;
        this.authenticator = authenticator;
        this.csrfManager = csrfManager;
        this.validator = validator;
        this.sanitizer = sanitizer;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();
        String clientIP = getClientIP(exchange);

        logger.log(Level.INFO, "CMS Request: {0} {1} from {2}", new Object[]{method, path, clientIP});

        // Login page doesn't require auth
        if (path.equals("/cms/login") && method.equals("GET")) {
            logger.log(Level.FINE, "Serving login page");
            sendHtmlResponse(exchange, 200, renderer.renderLoginPage());
            return;
        }

        if (path.equals("/cms/login") && method.equals("POST")) {
            handleLogin(exchange);
            return;
        }

        // Check authentication for all other CMS routes
        String sessionToken = getSessionToken(exchange);
        if (sessionToken == null || !authenticator.validateSession(sessionToken)) {
            logger.log(Level.WARNING, "Unauthorized access attempt to CMS: {0}", path);
            redirect(exchange, "/cms/login");
            return;
        }

        try {
            if (path.equals("/cms") || path.equals("/cms/")) {
                handleArticleList(exchange);
            } else if (path.equals("/cms/new")) {
                handleNewArticle(exchange, sessionToken);
            } else if (path.startsWith("/cms/edit/")) {
                handleEditArticle(exchange, path.substring(10), sessionToken);
            } else if (path.equals("/cms/save") && method.equals("POST")) {
                handleSaveArticle(exchange, sessionToken);
            } else if (path.startsWith("/cms/delete/")) {
                handleDeleteArticle(exchange, path.substring(12));
            } else if (path.equals("/cms/logout")) {
                handleLogout(exchange, sessionToken);
            } else {
                logger.log(Level.WARNING, "CMS route not found: {0}", path);
                sendResponse(exchange, 404, "Not Found");
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error handling CMS request: " + path, e);
            sendResponse(exchange, 500, "Internal Server Error: " + e.getMessage());
        }
    }

    private void handleLogin(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseFormData(exchange);
        String username = params.get("username");
        String password = params.get("password");

        logger.log(Level.INFO, "Login attempt for user: {0}", username);

        if (authenticator.authenticate(username, password)) {
            String sessionToken = authenticator.createSession();
            exchange.getResponseHeaders().add("Set-Cookie",
                    "session=" + sessionToken + "; Path=/; HttpOnly; Max-Age=86400");
            redirect(exchange, "/cms");
            logger.log(Level.INFO, "Successful login for user: {0}", username);
        } else {
            sendHtmlResponse(exchange, 401, renderer.renderLoginPage());
            logger.log(Level.WARNING, "Failed login attempt for user: {0}", username);
        }
    }

    private void handleLogout(HttpExchange exchange, String sessionToken) throws IOException {
        authenticator.invalidateSession(sessionToken);
        exchange.getResponseHeaders().add("Set-Cookie",
                "session=; Path=/; HttpOnly; Max-Age=0");
        redirect(exchange, "/");
        logger.log(Level.INFO, "User logged out");
    }

    private void handleArticleList(HttpExchange exchange) throws IOException {
        logger.log(Level.FINE, "Handling CMS article list request");
        List<Article> articles = repository.findAll();
        String html = renderer.renderArticleList(articles);
        sendHtmlResponse(exchange, 200, html);
    }

    private void handleNewArticle(HttpExchange exchange, String sessionToken) throws IOException {
        logger.log(Level.FINE, "Handling new article form request");
        String csrfToken = csrfManager.generateToken(sessionToken);
        String html = renderer.renderEditor(null, csrfToken);
        sendHtmlResponse(exchange, 200, html);
    }

    private void handleEditArticle(HttpExchange exchange, String slug, String sessionToken) throws IOException {
        logger.log(Level.FINE, "Handling edit article request for: {0}", slug);
        Optional<Article> article = repository.findBySlug(slug);
        if (article.isEmpty()) {
            logger.log(Level.WARNING, "Article not found for editing: {0}", slug);
            sendResponse(exchange, 404, "Article not found");
            return;
        }

        String csrfToken = csrfManager.generateToken(sessionToken);
        String html = renderer.renderEditor(article.get(), csrfToken);
        sendHtmlResponse(exchange, 200, html);
    }

    private void handleSaveArticle(HttpExchange exchange, String sessionToken) throws IOException {
        Map<String, String> params = parseFormData(exchange);

        // Validate CSRF
        if (!csrfManager.validateAndConsume(sessionToken, params.get("csrf"))) {
            logger.log(Level.WARNING, "CSRF validation failed for article save");
            sendResponse(exchange, 403, "Invalid CSRF token");
            return;
        }

        // Parse tags
        String tagsStr = params.getOrDefault("tags", "");
        List<String> tags = Arrays.stream(tagsStr.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        // Create article
        Article article = new ArticleImpl(
                params.get("id"),
                sanitizer.escapeHTML(params.get("title")),
                params.get("slug"),
                sanitizer.sanitizeHTML(params.get("content")),
                sanitizer.escapeHTML(params.getOrDefault("summary", "")),
                sanitizer.escapeHTML(params.get("author")),
                LocalDateTime.now(),
                LocalDateTime.now(),
                "true".equals(params.get("published")),
                tags
        );

        logger.log(Level.INFO, "Saving article: {0} (published: {1})",
                new Object[]{article.getSlug(), article.isPublished()});

        // Validate
        if (!validator.validate(article)) {
            String errorMsg = "Validation failed: " + String.join(", ", validator.getValidationErrors());
            logger.log(Level.WARNING, "Article validation failed: {0}", errorMsg);
            sendResponse(exchange, 400, errorMsg);
            return;
        }

        repository.save(article);
        redirect(exchange, "/cms");
        logger.log(Level.INFO, "Article saved successfully: {0}", article.getSlug());
    }

    private void handleDeleteArticle(HttpExchange exchange, String slug) throws IOException {
        logger.log(Level.INFO, "Deleting article: {0}", slug);
        boolean deleted = repository.delete(slug);
        if (deleted) {
            logger.log(Level.INFO, "Article deleted: {0}", slug);
        } else {
            logger.log(Level.WARNING, "Article not found for deletion: {0}", slug);
        }
        redirect(exchange, "/cms");
    }

    private String getClientIP(HttpExchange exchange) {
        String xForwardedFor = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    private String getSessionToken(HttpExchange exchange) {
        String cookies = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookies == null) return null;

        for (String cookie : cookies.split(";")) {
            String[] parts = cookie.trim().split("=", 2);
            if (parts.length == 2 && parts[0].equals("session")) {
                return parts[1];
            }
        }
        return null;
    }

    private Map<String, String> parseFormData(HttpExchange exchange) throws IOException {
        Map<String, String> params = new HashMap<>();
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

        for (String pair : body.split("&")) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                params.put(
                        java.net.URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8),
                        java.net.URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8)
                );
            }
        }
        return params;
    }

    private void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(302, -1);
        exchange.getResponseBody().close();
        logger.log(Level.FINE, "Redirect to: {0}", location);
    }

    private void sendHtmlResponse(HttpExchange exchange, int statusCode, String html) throws IOException {
        byte[] response = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, response.length);
        exchange.getResponseBody().write(response);
        exchange.getResponseBody().close();
        logger.log(Level.FINE, "Sent HTML response with status: {0}", statusCode);
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        byte[] response = message.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, response.length);
        exchange.getResponseBody().write(response);
        exchange.getResponseBody().close();
        logger.log(Level.FINE, "Sent response with status: {0}", statusCode);
    }
}

// ============================================================================
// SERVER IMPLEMENTATION
// ============================================================================

class SimpleArticleServer implements ArticleServer {
    private HttpServer server;
    private final ServerConfig config;
    private final ArticleRepository repository;
    private boolean running = false;
    private static final Logger logger = Logger.getLogger(SimpleArticleServer.class.getName());

    public SimpleArticleServer(ServerConfig config) throws IOException {
        this.config = config;
        this.repository = new FileArticleRepository(config.getStoragePath());
        setupLogging();
    }

    private void setupLogging() {
        try {
            LogManager.getLogManager().readConfiguration(
                    Main.class.getResourceAsStream("/logging.properties")
            );
        } catch (Exception e) {
            // Use default logging configuration
            Logger rootLogger = Logger.getLogger("");
            Handler[] handlers = rootLogger.getHandlers();
            if (handlers.length == 0) {
                ConsoleHandler handler = new ConsoleHandler();
                handler.setFormatter(new SimpleFormatter());
                rootLogger.addHandler(handler);
            }
        }
    }

    @Override
    public void start() throws IOException {
        HTMLSanitizer sanitizer = new SimpleHTMLSanitizer();
        ArticleValidator validator = new SimpleArticleValidator();
        ArticleRenderer articleRenderer = new SimpleArticleRenderer(sanitizer);
        CMSRenderer cmsRenderer = new SimpleCMSRenderer(sanitizer);
        CMSAuthenticator authenticator = new SimpleCMSAuthenticator(
                config.getCmsUsername(), config.getCmsPassword()
        );
        CSRFTokenManager csrfManager = new SimpleCSRFTokenManager();

        ArticleHandler articleHandler = new SimpleArticleHandler(repository, articleRenderer);
        CMSHandler cmsHandler = new SimpleCMSHandler(
                repository, cmsRenderer, authenticator, csrfManager, validator, sanitizer
        );

        server = HttpServer.create(
                new java.net.InetSocketAddress(config.getHost(), config.getPort()), 0
        );

        server.createContext("/", articleHandler::handle);
        server.createContext("/article/", articleHandler::handle);
        server.createContext("/cms", cmsHandler::handle);

        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(10));
        server.start();
        running = true;

        logger.log(Level.INFO, "ქართული ახალი ამბები started successfully!");
        logger.log(Level.INFO, "URL: http://localhost:{0}", config.getPort());
        logger.log(Level.INFO, "CMS: http://localhost:{0}/cms", config.getPort());
        logger.log(Level.INFO, "მომხმარებლის სახელი: {0}", config.getCmsUsername());
        logger.log(Level.WARNING, "Using default password - change immediately in config file!");
        logger.log(Level.INFO, "Press Ctrl+C to stop the server.");
    }

    @Override
    public void stop() {
        if (server != null) {
            server.stop(5);
            running = false;
            logger.log(Level.INFO, "Server stopped gracefully.");
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }
}

// ============================================================================
// MAIN CLASS
// ============================================================================

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        try {
            logger.info("Starting ქართული ახალი ამბები...");

            ServerConfig config = new SimpleServerConfig();
            SimpleArticleServer server = new SimpleArticleServer(config);

            // Shutdown hook for graceful shutdown
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Shutdown signal received, stopping server...");
                server.stop();
            }));

            server.start();
            // Keep main thread alive
            Thread.currentThread().join();

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start server: " + e.getMessage(), e);
            System.exit(1);
        }
    }
}