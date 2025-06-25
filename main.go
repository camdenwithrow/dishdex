package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"

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
	_ "github.com/mattn/go-sqlite3"
)

var PORT = "4444"

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
	db    *sql.DB
	store *sessions.CookieStore
}

func main() {
	db, err := initDB()
	if err != nil {
		log.Fatal("Failed to connect to db ", err)
	}
	defer db.Close()

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.Static("/static", "ui/static")

	// --- Auth Setup ---
	key := os.Getenv("SESSION_SECRET")
	if key == "" {
		key = "dev_secret_key" // fallback for dev
	}
	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(86400 * 30)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = false // set true in prod
	gothic.Store = store

	handler := &Handler{db: db, store: store}

	goth.UseProviders(
		github.New(
			os.Getenv("GITHUB_CLIENT_ID"),
			os.Getenv("GITHUB_CLIENT_SECRET"),
			"http://localhost:"+PORT+"/auth/github/callback",
		),
	)

	// --- Helper Middleware to set login state ---
	e.Use(handler.authSessionMiddleware)

	// --- Auth Routes ---
	e.GET("/auth/:provider", handler.beginAuth)
	e.GET("/auth/:provider/callback", handler.authCallback)
	e.POST("/logout", handler.logout)
	// Routes
	e.GET("/", home)
	e.GET("/health", health)
	e.GET("/recipes/new", handler.showAddRecipeForm)
	e.POST("/recipes", handler.createRecipe)
	e.GET("/recipes", handler.listRecipes)
	e.POST("/recipes/search", handler.searchRecipes)
	e.GET("/recipes/:id", handler.getRecipe)
	e.PUT("/recipes/:id", handler.updateRecipe)
	e.DELETE("/recipes/:id", handler.deleteRecipe)
	e.GET("/recipes/:id/edit", handler.showEditRecipeForm)

	e.Logger.Fatal(e.Start(":" + PORT))
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "dishdex.db")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	createRecipesTable := `
	CREATE TABLE IF NOT EXISTS recipes (
		id TEXT PRIMARY KEY,
		title TEXT NOT NULL,
		description TEXT NULL,
		cook_time TEXT NULL,
		ingredients TEXT,
		instructions TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(createRecipesTable)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return db, nil
}

func health(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"status": "healthy",
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

func (h *Handler) authSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := h.store.Get(c.Request(), "auth-session")
		if _, ok := sess.Values["user_id"]; ok {
			c.Set("loggedIn", true)
			c.Set("userName", sess.Values["name"])
		} else {
			c.Set("loggedIn", false)
		}
		return next(c)
	}
}

func (h *Handler) beginAuth(c echo.Context) error {
	provider := c.Param("provider")
	ctx := context.WithValue(c.Request().Context(), gothic.ProviderParamKey, provider)
	r := c.Request().WithContext(ctx)
	gothic.BeginAuthHandler(c.Response().Writer, r)
	return nil
}

func (h *Handler) authCallback(c echo.Context) error {
	user, err := gothic.CompleteUserAuth(c.Response().Writer, c.Request())
	if err != nil {
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}
	// Use NickName if Name is empty
	name := user.Name
	if name == "" {
		name = user.NickName
	}
	// Save user info in DB (upsert)
	_, err = h.db.Exec(`INSERT INTO users (id, name, email, avatar_url) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, email=excluded.email, avatar_url=excluded.avatar_url`,
		user.UserID, name, user.Email, user.AvatarURL)
	if err != nil {
		log.Printf("Failed to upsert user: %v", err)
	}
	// Save user info in session
	sess, _ := h.store.Get(c.Request(), "auth-session")
	sess.Values["user_id"] = user.UserID
	sess.Values["name"] = name
	sess.Values["email"] = user.Email
	sess.Values["avatar_url"] = user.AvatarURL
	sess.Save(c.Request(), c.Response().Writer)
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) logout(c echo.Context) error {
	sess, _ := h.store.Get(c.Request(), "auth-session")
	sess.Options.MaxAge = -1
	sess.Save(c.Request(), c.Response().Writer)
	gothic.Logout(c.Response().Writer, c.Request())
	return c.Redirect(http.StatusSeeOther, "/")
}

func (h *Handler) createRecipe(c echo.Context) error {
	title := c.FormValue("title")
	description := c.FormValue("description")
	cookTime := c.FormValue("cookTime")
	ingredients := c.FormValue("ingredients")
	instructions := c.FormValue("instructions")

	if title == "" || ingredients == "" || instructions == "" {
		return c.String(http.StatusBadRequest, "Missing required fields")
	}

	id := uuid.New().String()
	_, err := h.db.Exec(`INSERT INTO recipes (id, title, description, cook_time, ingredients, instructions) VALUES (?, ?, ?, ?, ?, ?)`,
		id, title, nullIfEmpty(description), nullIfEmpty(cookTime), ingredients, instructions)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to create recipe")
	}

	if isHtmxReq(c) {
		return h.listRecipes(c)
	}

	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) listRecipes(c echo.Context) error {
	rows, err := h.db.Query(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes ORDER BY created_at DESC`)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to fetch recipes")
	}
	defer rows.Close()

	recipes := []Recipe{}

	for rows.Next() {
		var r Recipe
		var description, cookTime sql.NullString
		if err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt); err != nil {
			return c.String(http.StatusInternalServerError, "Failed to parse recipe")
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		recipes = append(recipes, r)
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

	sess, _ := h.store.Get(c.Request(), "auth-session")
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

func (h *Handler) getRecipe(c echo.Context) error {
	id := c.Param("id")
	var r Recipe
	var description, cookTime sql.NullString
	err := h.db.QueryRow(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes WHERE id = ?`, id).
		Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
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

	sess, _ := h.store.Get(c.Request(), "auth-session")
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
	id := c.Param("id")
	title := c.FormValue("title")
	description := c.FormValue("description")
	cookTime := c.FormValue("cookTime")
	ingredients := c.FormValue("ingredients")
	instructions := c.FormValue("instructions")

	if title == "" || ingredients == "" || instructions == "" {
		return c.String(http.StatusBadRequest, "Missing required fields")
	}

	_, err := h.db.Exec(`UPDATE recipes SET title=?, description=?, cook_time=?, ingredients=?, instructions=? WHERE id=?`,
		title, nullIfEmpty(description), nullIfEmpty(cookTime), ingredients, instructions, id)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to update recipe")
	}
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) deleteRecipe(c echo.Context) error {
	id := c.Param("id")

	var exists int
	err := h.db.QueryRow(`SELECT 1 FROM recipes WHERE id = ?`, id).Scan(&exists)
	if err == sql.ErrNoRows {
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to check recipe")
	}

	_, err = h.db.Exec(`DELETE FROM recipes WHERE id = ?`, id)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to delete recipe")
	}

	if isHtmxReq(c) {
		c.Response().Header().Set("HX-Push-Url", "/recipes")
		return h.listRecipes(c)
	}

	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handler) searchRecipes(c echo.Context) error {
	query := c.FormValue("search")

	if query == "" {
		return h.listRecipes(c)
	}

	searchPattern := "%" + strings.ReplaceAll(strings.ReplaceAll(query, "%", "\\%"), "_", "\\_") + "%"
	rows, err := h.db.Query(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes WHERE title LIKE ? OR description LIKE ? ORDER BY created_at DESC`, searchPattern, searchPattern)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to search recipes")
	}
	defer rows.Close()

	recipes := []Recipe{}

	for rows.Next() {
		var r Recipe
		var description, cookTime sql.NullString
		if err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt); err != nil {
			return c.String(http.StatusInternalServerError, "Failed to parse recipe")
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		recipes = append(recipes, r)
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

	sess, _ := h.store.Get(c.Request(), "auth-session")
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
	id := c.Param("id")
	var r Recipe
	var description, cookTime sql.NullString
	err := h.db.QueryRow(`SELECT id, title, description, cook_time, ingredients, instructions, created_at FROM recipes WHERE id = ?`, id).
		Scan(&r.ID, &r.Title, &description, &cookTime, &r.Ingredients, &r.Instructions, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
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

	sess, _ := h.store.Get(c.Request(), "auth-session")
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
