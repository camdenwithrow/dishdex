package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/camdenwithrow/dishdex/ui"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

// Configuration
type Config struct {
	Port               string
	Env                string
	LogLevel           string
	SessionSecret      string
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string
	DatabaseURL        string
	BaseURL            string
}

func loadConfig() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		if env == "production" {
			baseURL = "https://yourdomain.com" // Update this for production
		} else {
			baseURL = "http://localhost:" + port
		}
	}

	return &Config{
		Port:               port,
		Env:                env,
		LogLevel:           os.Getenv("LOG_LEVEL"),
		SessionSecret:      os.Getenv("SESSION_SECRET"),
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		BaseURL:            baseURL,
	}
}

type Recipe struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	CookTime     string `json:"cook_time"`
	Ingredients  string `json:"ingredients"`
	Instructions string `json:"instructions"`
	CreatedAt    string `json:"created_at"`
}

type Handler struct {
	db     *sql.DB
	store  *sessions.CookieStore
	logger *slog.Logger
}

type EchoLogger struct {
	logger *slog.Logger
}

func (l *EchoLogger) Write(p []byte) (n int, err error) {
	l.logger.Info("echo", "message", string(p))
	return len(p), nil
}

func main() {
	config := loadConfig()

	logger := setupLogger(config)
	slog.SetDefault(logger)

	logger.Info("Starting DishDex application",
		"port", config.Port,
		"env", config.Env,
		"base_url", config.BaseURL)

	// Validate required configuration
	if config.Env == "production" {
		if config.SessionSecret == "" || config.SessionSecret == "dev_secret_key" {
			logger.Error("SESSION_SECRET is required in production")
			os.Exit(1)
		}
		if config.GitHubClientID == "" || config.GitHubClientSecret == "" {
			logger.Warn("GitHub OAuth credentials not configured")
		}
		if config.GoogleClientID == "" || config.GoogleClientSecret == "" {
			logger.Warn("Google OAuth credentials not configured")
		}
	}

	db, err := initDB(config)
	if err != nil {
		logger.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	logger.Info("Database connection established")

	e := echo.New()

	// Disable Echo's default logger
	e.Logger.SetOutput(io.Discard)
	e.Logger.SetLevel(0) // Disable all Echo logging levels

	// --- Auth Setup ---
	sessionSecret := config.SessionSecret
	if sessionSecret == "" {
		sessionSecret = "dev_secret_key"
		logger.Warn("Using default session secret - not recommended for production")
	}

	store := sessions.NewCookieStore([]byte(sessionSecret))
	store.MaxAge(86400 * 30) // 30 days
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = config.Env == "production" // HTTPS only in production
	store.Options.SameSite = http.SameSiteLaxMode
	gothic.Store = store

	handler := &Handler{db: db, store: store, logger: logger}

	// Setup OAuth providers with proper callback URLs
	if config.GitHubClientID != "" && config.GitHubClientSecret != "" {
		githubCallback := config.BaseURL + "/auth/github/callback"
		goth.UseProviders(
			github.New(config.GitHubClientID, config.GitHubClientSecret, githubCallback),
		)
		logger.Info("GitHub OAuth provider configured", "callback", githubCallback)
	}

	if config.GoogleClientID != "" && config.GoogleClientSecret != "" {
		googleCallback := config.BaseURL + "/auth/google/callback"
		goth.UseProviders(
			google.New(config.GoogleClientID, config.GoogleClientSecret, googleCallback),
		)
		logger.Info("Google OAuth provider configured", "callback", googleCallback)
	}

	// Middleware
	e.Use(handler.requestLoggerMiddleware)
	e.Use(middleware.Recover())

	// CORS configuration
	corsConfig := middleware.CORSConfig{
		AllowOrigins: []string{"*"}, // Configure appropriately for production
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}
	e.Use(middleware.CORSWithConfig(corsConfig))

	e.Use(handler.authSessionMiddleware)

	// Security headers
	e.Use(middleware.Secure())
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20))) // 20 requests per second

	e.Static("/static", "ui/static")

	// Auth Routes
	e.GET("/auth/:provider", handler.beginAuth)
	e.GET("/auth/:provider/callback", handler.authCallback)
	e.POST("/logout", handler.logout)
	e.GET("/", home)
	e.GET("/signin", signIn)
	e.GET("/health", health)
	e.GET("/complete-profile", handler.completeProfileForm)
	e.POST("/complete-profile", handler.completeProfileSubmit)

	// Routes
	recipes := e.Group("/recipes", requireLogin)
	recipes.GET("", handler.listRecipes)
	recipes.GET("/new", handler.showAddRecipeForm)
	recipes.POST("", handler.createRecipe)
	recipes.POST("/search", handler.searchRecipes)
	recipes.GET("/:id", handler.getRecipe)
	recipes.PUT("/:id", handler.updateRecipe)
	recipes.DELETE("/:id", handler.deleteRecipe)
	recipes.GET("/:id/edit", handler.showEditRecipeForm)

	logger.Info("Server starting", "port", config.Port)
	e.Logger.Fatal(e.Start(":" + config.Port))
}

func setupLogger(config *Config) *slog.Logger {
	logLevel := slog.LevelInfo
	if levelStr := config.LogLevel; levelStr != "" {
		switch strings.ToUpper(levelStr) {
		case "DEBUG":
			logLevel = slog.LevelDebug
		case "INFO":
			logLevel = slog.LevelInfo
		case "WARN":
			logLevel = slog.LevelWarn
		case "ERROR":
			logLevel = slog.LevelError
		}
	}

	opts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: false, // Disable source info for cleaner logs
	}

	var handler slog.Handler
	if config.Env == "production" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = &DevHandler{
			opts: opts,
		}
	}
	return slog.New(handler)
}

type DevHandler struct {
	opts *slog.HandlerOptions
}

func (h *DevHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *DevHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *DevHandler) WithGroup(name string) slog.Handler {
	return h
}

func (h *DevHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelDebug {
		msg := r.Message
		if !strings.Contains(msg, "User authenticated") &&
			!strings.Contains(msg, "User not authenticated") &&
			!strings.Contains(msg, "Login required") {
			return nil
		}
	}

	var parts []string
	parts = append(parts, r.Time.Format("15:04:05"))

	levelStr := strings.ToUpper(r.Level.String())
	switch r.Level {
	case slog.LevelError:
		levelStr = "\033[31m" + levelStr + "\033[0m" // Red
	case slog.LevelWarn:
		levelStr = "\033[33m" + levelStr + "\033[0m" // Yellow
	case slog.LevelInfo:
		levelStr = "\033[36m" + levelStr + "\033[0m" // Cyan
	case slog.LevelDebug:
		levelStr = "\033[37m" + levelStr + "\033[0m" // Gray
	}
	parts = append(parts, levelStr)
	parts = append(parts, r.Message)

	if r.NumAttrs() > 0 {
		var attrs []string
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "user_agent" || a.Key == "remote_addr" || a.Key == "size" {
				return true
			}

			value := a.Value.String()
			if a.Value.Kind() == slog.KindString && len(value) > 50 {
				value = value[:47] + "..."
			}
			attrs = append(attrs, a.Key+"="+value)
			return true
		})

		if len(attrs) > 0 {
			parts = append(parts, "("+strings.Join(attrs, ", ")+")")
		}
	}

	fmt.Println(strings.Join(parts, " "))
	return nil
}

func (h *Handler) requestLoggerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()

		req := c.Request()
		path := req.URL.Path
		method := req.Method

		isHtmx := isHtmxReq(c)

		// Only log non-static requests and non-health checks
		if !strings.HasPrefix(path, "/static") && path != "/health" {
			h.logger.Debug("Request started", "method", method, "path", path, "htmx", isHtmx)
		}

		err := next(c)
		duration := time.Since(start)
		status := c.Response().Status

		if !strings.HasPrefix(path, "/static") && path != "/health" {
			logLevel := slog.LevelInfo
			if status >= 400 {
				logLevel = slog.LevelWarn
			}
			if status >= 500 {
				logLevel = slog.LevelError
			}

			h.logger.Log(context.Background(), logLevel, "Request completed",
				"method", method,
				"path", path,
				"status", status,
				"duration", duration,
				"htmx", isHtmx,
			)
		}
		return err
	}
}

func initDB(config *Config) (*sql.DB, error) {
	dbUrl := config.DatabaseURL
	dbToken := os.Getenv("TURSO_AUTH_TOKEN")
	var db *sql.DB
	var err error

	// If no database URL is provided, use local SQLite
	if dbUrl == "" {
		dbUrl = "dishdex.db"
	}

	// Check if it's a Turso database URL (contains libsql://)
	if strings.Contains(dbUrl, "libsql://") {
		if dbToken == "" {
			return nil, fmt.Errorf("TURSO_AUTH_TOKEN is required for Turso database")
		}
		dbUrlFull := dbUrl + "?authToken=" + dbToken
		db, err = sql.Open("libsql", dbUrlFull)
		slog.Info("Connecting to Turso database", "url", dbUrl)
	} else {
		// Local SQLite database
		db, err = sql.Open("sqlite3", dbUrl)
		slog.Info("Connecting to local SQLite database", "file", dbUrl)
	}

	if err != nil {
		return nil, err
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	// Create tables if they don't exist
	createRecipesTable := `
	CREATE TABLE IF NOT EXISTS recipes (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT NULL,
		cook_time TEXT NULL,
		ingredients TEXT,
		instructions TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	`
	_, err = db.Exec(createRecipesTable)
	if err != nil {
		return nil, fmt.Errorf("failed to create recipes table: %w", err)
	}

	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		name TEXT,
		email TEXT,
		avatar_url TEXT
	);
	`
	_, err = db.Exec(createUsersTable)
	if err != nil {
		return nil, fmt.Errorf("failed to create users table: %w", err)
	}

	slog.Info("Database tables initialized successfully")
	return db, nil
}

func health(c echo.Context) error {
	// Get config from context or use default
	config := c.Get("config")
	if config != nil {
		if cfg, ok := config.(*Config); ok && cfg.LogLevel == "DEBUG" {
			slog.Debug("Health check requested")
		}
	} else if os.Getenv("LOG_LEVEL") == "DEBUG" {
		slog.Debug("Health check requested")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func render(c echo.Context, component templ.Component) error {
	return component.Render(c.Request().Context(), c.Response().Writer)
}

func home(c echo.Context) error {
	loggedIn, _ := c.Get("loggedIn").(bool)
	if loggedIn {
		return c.Redirect(http.StatusSeeOther, "/recipes")
	}
	if isHtmxReq(c) {
		return render(c, ui.Home())
	}
	return render(c, ui.Base(ui.Home(), false, nil))
}

func signIn(c echo.Context) error {
	loggedIn, _ := c.Get("loggedIn").(bool)
	if loggedIn {
		return c.Redirect(http.StatusSeeOther, "/recipes")
	}
	return render(c, ui.Base(ui.SignInPage(), false, nil))
}

func (h *Handler) authSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := h.store.Get(c.Request(), "auth-session")
		if _, ok := sess.Values["user_id"]; ok {
			userID := toString(sess.Values["user_id"])
			userName := toString(sess.Values["name"])
			c.Set("loggedIn", true)
			c.Set("userName", userName)
			// Only log authentication on first request or when debugging
			if os.Getenv("LOG_LEVEL") == "DEBUG" {
				h.logger.Debug("User authenticated", "user_id", userID, "name", userName)
			}
		} else {
			c.Set("loggedIn", false)
		}
		return next(c)
	}
}

func (h *Handler) beginAuth(c echo.Context) error {
	provider := c.Param("provider")
	h.logger.Info("Starting OAuth authentication", "provider", provider)

	ctx := context.WithValue(c.Request().Context(), gothic.ProviderParamKey, provider)
	r := c.Request().WithContext(ctx)
	gothic.BeginAuthHandler(c.Response().Writer, r)
	return nil
}

func (h *Handler) authCallback(c echo.Context) error {
	user, err := gothic.CompleteUserAuth(c.Response().Writer, c.Request())
	if err != nil {
		h.logger.Error("OAuth authentication failed", "error", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	h.logger.Info("OAuth authentication successful",
		"provider", user.Provider,
		"user_id", user.UserID,
		"name", user.Name,
		"email", user.Email,
	)

	// Use NickName if Name is empty
	name := user.Name
	if name == "" {
		name = user.NickName
	}

	dbEmail := ""
	if user.Email == "" {
		// Try to get email from DB
		row := h.db.QueryRow(`SELECT email FROM users WHERE id = ?`, user.UserID)
		var emailFromDB sql.NullString
		if err := row.Scan(&emailFromDB); err == nil && emailFromDB.Valid {
			dbEmail = emailFromDB.String
			h.logger.Debug("Retrieved email from database", "user_id", user.UserID, "email", dbEmail)
		}
	}

	// Always upsert name and avatar, only update email if present
	if user.Email != "" {
		_, err = h.db.Exec(`INSERT INTO users (id, name, email, avatar_url) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, email=excluded.email, avatar_url=excluded.avatar_url`,
			user.UserID, name, user.Email, user.AvatarURL)
	} else {
		_, err = h.db.Exec(`INSERT INTO users (id, name, avatar_url) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, avatar_url=excluded.avatar_url`,
			user.UserID, name, user.AvatarURL)
	}
	if err != nil {
		h.logger.Error("Failed to upsert user", "error", err, "user_id", user.UserID)
	} else {
		h.logger.Info("User upserted successfully", "user_id", user.UserID, "name", name)
	}

	sess, _ := h.store.Get(c.Request(), "auth-session")
	sess.Values["user_id"] = user.UserID
	sess.Values["name"] = name
	sess.Values["avatar_url"] = user.AvatarURL

	finalEmail := user.Email
	if finalEmail == "" {
		finalEmail = dbEmail
	}
	if finalEmail != "" {
		sess.Values["email"] = finalEmail
	} else {
		delete(sess.Values, "email")
	}
	sess.Save(c.Request(), c.Response().Writer)

	if finalEmail == "" {
		h.logger.Info("User needs to complete profile", "user_id", user.UserID)
		return c.Redirect(http.StatusSeeOther, "/complete-profile")
	}

	h.logger.Info("User authentication completed", "user_id", user.UserID, "name", name)
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) logout(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	userName := toString(sess.Values["name"])

	h.logger.Info("User logging out", "user_id", userID, "name", userName)

	sess.Options.MaxAge = -1
	sess.Save(c.Request(), c.Response().Writer)
	gothic.Logout(c.Response().Writer, c.Request())
	return c.Redirect(http.StatusSeeOther, "/")
}

func (h *Handler) createRecipe(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized recipe creation attempt")
		return c.String(http.StatusUnauthorized, "Not authenticated")
	}

	title := c.FormValue("title")
	description := c.FormValue("description")
	cookTime := c.FormValue("cookTime")
	ingredients := c.FormValue("ingredients")
	instructions := c.FormValue("instructions")

	if title == "" || ingredients == "" || instructions == "" {
		h.logger.Warn("Recipe creation failed - missing required fields", "user_id", userID, "title", title)
		return c.String(http.StatusBadRequest, "Missing required fields")
	}

	id := uuid.New().String()
	_, err := h.db.Exec(`INSERT INTO recipes (id, user_id, title, description, cook_time, ingredients, instructions) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, userID, title, nullIfEmpty(description), nullIfEmpty(cookTime), ingredients, instructions)
	if err != nil {
		h.logger.Error("Failed to create recipe", "error", err, "user_id", userID, "title", title)
		return c.String(http.StatusInternalServerError, "Failed to create recipe")
	}

	h.logger.Info("Recipe created successfully", "recipe_id", id, "user_id", userID, "title", title)

	if isHtmxReq(c) {
		return h.listRecipes(c)
	}

	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) listRecipes(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized recipe list attempt")
		return c.String(http.StatusUnauthorized, "Not authenticated")
	}

	rows, err := h.db.Query(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		h.logger.Error("Failed to fetch recipes", "error", err, "user_id", userID)
		return c.String(http.StatusInternalServerError, "Failed to fetch recipes")
	}
	defer rows.Close()

	recipes := []Recipe{}

	for rows.Next() {
		var r Recipe
		var description, cookTime sql.NullString
		if err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt); err != nil {
			h.logger.Error("Failed to parse recipe", "error", err, "user_id", userID)
			return c.String(http.StatusInternalServerError, "Failed to parse recipe")
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		recipes = append(recipes, r)
	}

	// Only log recipe count in debug mode
	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		h.logger.Debug("Recipes fetched", "user_id", userID, "count", len(recipes))
	}

	// Convert []Recipe to []ui.Recipe for the template
	tRecipes := make([]ui.Recipe, len(recipes))
	for i, r := range recipes {
		tRecipes[i] = ui.Recipe{
			ID:          r.ID,
			Title:       r.Title,
			Description: r.Description,
			CookTime:    r.CookTime,
		}
	}

	user := &ui.User{
		ID:        toString(sess.Values["user_id"]),
		Name:      toString(sess.Values["name"]),
		Email:     toString(sess.Values["email"]),
		AvatarURL: toString(sess.Values["avatar_url"]),
	}
	loggedIn := user.Email != ""
	if isHtmxReq(c) {
		return render(c, ui.RecipesList(tRecipes, []string{}, []string{}))
	}
	return render(c, ui.Base(ui.RecipesList(tRecipes, []string{}, []string{}), loggedIn, user))
}

func (h *Handler) getRecipe(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized recipe access attempt")
		return c.String(http.StatusUnauthorized, "Not authenticated")
	}

	id := c.Param("id")
	var r Recipe
	var description, cookTime sql.NullString
	err := h.db.QueryRow(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes WHERE id = ? AND user_id = ?`, id, userID).
		Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt)
	if err == sql.ErrNoRows {
		h.logger.Warn("Recipe not found", "recipe_id", id, "user_id", userID)
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
		h.logger.Error("Failed to fetch recipe", "error", err, "recipe_id", id, "user_id", userID)
		return c.String(http.StatusInternalServerError, "Failed to fetch recipe")
	}

	r.Description = nullStringToString(description)
	r.CookTime = nullStringToString(cookTime)

	h.logger.Debug("Recipe fetched", "recipe_id", id, "user_id", userID, "title", r.Title)

	recipeDetail := ui.RecipeDetail{
		ID:           r.ID,
		Title:        r.Title,
		Description:  r.Description,
		CookTime:     r.CookTime,
		Ingredients:  r.Ingredients,
		Instructions: r.Instructions,
		CreatedAt:    r.CreatedAt,
	}

	user := &ui.User{
		ID:        toString(sess.Values["user_id"]),
		Name:      toString(sess.Values["name"]),
		Email:     toString(sess.Values["email"]),
		AvatarURL: toString(sess.Values["avatar_url"]),
	}
	loggedIn := user.Name != ""
	if isHtmxReq(c) {
		return render(c, ui.ShowRecipe(recipeDetail))
	}
	return render(c, ui.Base(ui.ShowRecipe(recipeDetail), loggedIn, user))
}

func (h *Handler) updateRecipe(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized recipe update attempt")
		return c.String(http.StatusUnauthorized, "Not authenticated")
	}

	id := c.Param("id")
	title := c.FormValue("title")
	description := c.FormValue("description")
	cookTime := c.FormValue("cookTime")
	ingredients := c.FormValue("ingredients")
	instructions := c.FormValue("instructions")

	if title == "" || ingredients == "" || instructions == "" {
		h.logger.Warn("Recipe update failed - missing required fields", "recipe_id", id, "user_id", userID)
		return c.String(http.StatusBadRequest, "Missing required fields")
	}

	_, err := h.db.Exec(`UPDATE recipes SET title=?, description=?, cook_time=?, ingredients=?, instructions=? WHERE id=? AND user_id=?`,
		title, nullIfEmpty(description), nullIfEmpty(cookTime), ingredients, instructions, id, userID)
	if err != nil {
		h.logger.Error("Failed to update recipe", "error", err, "recipe_id", id, "user_id", userID)
		return c.String(http.StatusInternalServerError, "Failed to update recipe")
	}

	h.logger.Info("Recipe updated successfully", "recipe_id", id, "user_id", userID, "title", title)
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) deleteRecipe(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized recipe deletion attempt")
		return c.String(http.StatusUnauthorized, "Not authenticated")
	}

	id := c.Param("id")

	var exists int
	err := h.db.QueryRow(`SELECT 1 FROM recipes WHERE id = ? AND user_id = ?`, id, userID).Scan(&exists)
	if err == sql.ErrNoRows {
		h.logger.Warn("Recipe not found for deletion", "recipe_id", id, "user_id", userID)
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
		h.logger.Error("Failed to check recipe existence", "error", err, "recipe_id", id, "user_id", userID)
		return c.String(http.StatusInternalServerError, "Failed to check recipe")
	}

	_, err = h.db.Exec(`DELETE FROM recipes WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		h.logger.Error("Failed to delete recipe", "error", err, "recipe_id", id, "user_id", userID)
		return c.String(http.StatusInternalServerError, "Failed to delete recipe")
	}

	h.logger.Info("Recipe deleted successfully", "recipe_id", id, "user_id", userID)

	if isHtmxReq(c) {
		c.Response().Header().Set("HX-Push-Url", "/recipes")
		return h.listRecipes(c)
	}

	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) searchRecipes(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized recipe search attempt")
		return c.String(http.StatusUnauthorized, "Not authenticated")
	}

	query := c.FormValue("search")

	if query == "" {
		return h.listRecipes(c)
	}

	// Only log search queries in debug mode
	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		h.logger.Debug("Searching recipes", "user_id", userID, "query", query)
	}

	searchPattern := "%" + strings.ReplaceAll(strings.ReplaceAll(query, "%", "\\%"), "_", "\\_") + "%"
	rows, err := h.db.Query(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes WHERE user_id = ? AND (title LIKE ? OR description LIKE ?) ORDER BY created_at DESC`, userID, searchPattern, searchPattern)
	if err != nil {
		h.logger.Error("Failed to search recipes", "error", err, "user_id", userID, "query", query)
		return c.String(http.StatusInternalServerError, "Failed to search recipes")
	}
	defer rows.Close()

	recipes := []Recipe{}

	for rows.Next() {
		var r Recipe
		var description, cookTime sql.NullString
		if err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt); err != nil {
			h.logger.Error("Failed to parse recipe during search", "error", err, "user_id", userID)
			return c.String(http.StatusInternalServerError, "Failed to parse recipe")
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		recipes = append(recipes, r)
	}

	// Only log search results in debug mode
	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		h.logger.Debug("Search completed", "user_id", userID, "query", query, "results", len(recipes))
	}

	// Convert []Recipe to []ui.Recipe for the template
	tRecipes := make([]ui.Recipe, len(recipes))
	for i, r := range recipes {
		tRecipes[i] = ui.Recipe{
			ID:          r.ID,
			Title:       r.Title,
			Description: r.Description,
			CookTime:    r.CookTime,
		}
	}

	user := &ui.User{
		ID:        toString(sess.Values["user_id"]),
		Name:      toString(sess.Values["name"]),
		Email:     toString(sess.Values["email"]),
		AvatarURL: toString(sess.Values["avatar_url"]),
	}
	loggedIn := user.Name != ""
	if isHtmxReq(c) {
		return render(c, ui.RecipesList(tRecipes, []string{}, []string{}))
	}
	return render(c, ui.Base(ui.RecipesList(tRecipes, []string{}, []string{}), loggedIn, user))
}

func (h *Handler) showAddRecipeForm(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	user := &ui.User{
		ID:        toString(sess.Values["user_id"]),
		Name:      toString(sess.Values["name"]),
		Email:     toString(sess.Values["email"]),
		AvatarURL: toString(sess.Values["avatar_url"]),
	}
	loggedIn := user.Name != ""
	if isHtmxReq(c) {
		return render(c, ui.AddRecipe())
	}
	return render(c, ui.Base(ui.AddRecipe(), loggedIn, user))
}

func (h *Handler) showEditRecipeForm(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized recipe edit form access attempt")
		return c.String(http.StatusUnauthorized, "Not authenticated")
	}

	id := c.Param("id")
	var r Recipe
	var description, cookTime sql.NullString
	err := h.db.QueryRow(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes WHERE id = ? AND user_id = ?`, id, userID).
		Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt)
	if err == sql.ErrNoRows {
		h.logger.Warn("Recipe not found for edit", "recipe_id", id, "user_id", userID)
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
		h.logger.Error("Failed to fetch recipe for edit", "error", err, "recipe_id", id, "user_id", userID)
		return c.String(http.StatusInternalServerError, "Failed to fetch recipe")
	}

	r.Description = nullStringToString(description)
	r.CookTime = nullStringToString(cookTime)

	recipeDetail := ui.RecipeDetail{
		ID:           r.ID,
		Title:        r.Title,
		Description:  r.Description,
		CookTime:     r.CookTime,
		Ingredients:  r.Ingredients,
		Instructions: r.Instructions,
		CreatedAt:    r.CreatedAt,
	}

	user := &ui.User{
		ID:        toString(sess.Values["user_id"]),
		Name:      toString(sess.Values["name"]),
		Email:     toString(sess.Values["email"]),
		AvatarURL: toString(sess.Values["avatar_url"]),
	}
	loggedIn := user.Name != ""
	if isHtmxReq(c) {
		return render(c, ui.EditRecipe(recipeDetail))
	}
	return render(c, ui.Base(ui.EditRecipe(recipeDetail), loggedIn, user))
}

func isHtmxReq(c echo.Context) bool {
	return c.Request().Header.Get("HX-Request") == "true"
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// Helper to convert interface{} to string
func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func requireLogin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		loggedIn, _ := c.Get("loggedIn").(bool)
		if !loggedIn {
			slog.Debug("Login required - redirecting to home")
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return next(c)
	}
}

func (h *Handler) completeProfileForm(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized profile completion form access")
		return c.Redirect(http.StatusSeeOther, "/signin")
	}

	// Only log in debug mode
	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		h.logger.Debug("Profile completion form accessed", "user_id", userID)
	}
	return render(c, ui.Base(ui.CompleteProfileForm(), false, nil))
}

func (h *Handler) completeProfileSubmit(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	userID := toString(sess.Values["user_id"])
	if userID == "" {
		h.logger.Warn("Unauthorized profile completion submission")
		return c.Redirect(http.StatusSeeOther, "/signin")
	}

	email := c.FormValue("email")
	if email == "" {
		h.logger.Warn("Profile completion failed - email required", "user_id", userID)
		return render(c, ui.CompleteProfileFormWithError("Email is required"))
	}

	// Update user in DB
	_, err := h.db.Exec(`UPDATE users SET email=? WHERE id=?`, email, userID)
	if err != nil {
		h.logger.Error("Failed to update user email", "error", err, "user_id", userID, "email", email)
		return c.String(http.StatusInternalServerError, "Failed to update email")
	}

	h.logger.Info("User profile completed", "user_id", userID, "email", email)

	sess.Values["email"] = email
	sess.Save(c.Request(), c.Response().Writer)
	return c.Redirect(http.StatusSeeOther, "/recipes")
}
