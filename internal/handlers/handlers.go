package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"database/sql"

	"github.com/a-h/templ"
	"github.com/camdenwithrow/dishdex/internal/auth"
	"github.com/camdenwithrow/dishdex/internal/config"
	l "github.com/camdenwithrow/dishdex/internal/logger"
	"github.com/camdenwithrow/dishdex/internal/models"
	"github.com/camdenwithrow/dishdex/internal/templates"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type Handlers struct {
	cfg         *config.Config
	db          *sql.DB
	AuthService *auth.AuthService
	logger      *l.Logger
}

func NewHandlers(cfg *config.Config, db *sql.DB, authService *auth.AuthService, logger *l.Logger) *Handlers {
	return &Handlers{cfg, db, authService, logger}
}

func IsHtmxReq(c echo.Context) bool {
	return c.Request().Header.Get("HX-Request") == "true"
}

func render(c echo.Context, page templ.Component, htmxComponent templ.Component) error {
	component := page
	if isHtmxReq(c) && htmxComponent != nil {
		component = htmxComponent
	}
	return component.Render(c.Request().Context(), c.Response().Writer)
}

func defaultRender(c echo.Context, t templ.Component, user *models.User) error {
	return render(c, templates.Default(t, user), t)
}

func renderSingle(c echo.Context, t templ.Component) error {
	return render(c, t, nil)
}

func (h *Handlers) Health(c echo.Context) error {
	if h.cfg == nil {
		h.cfg = config.LoadConfig()
	}

	if h.cfg.LogLevel == "DEBUG" {
		h.logger.Debug("Health check requested")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"status":      "healthy",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"environment": h.cfg.Env,
	})
}

func (h *Handlers) Home(c echo.Context) error {
	if loggedIn, err := h.AuthService.LoggedIn(c); err != nil || !loggedIn {
		return defaultRender(c, templates.Home(), nil)
	}
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handlers) BeginAuth(c echo.Context) error {
	provider := c.Param("provider")
	h.logger.Info("Starting OAuth authentication", "provider", provider)

	ctx := context.WithValue(c.Request().Context(), gothic.ProviderParamKey, provider)
	r := c.Request().WithContext(ctx)

	if user, err := gothic.CompleteUserAuth(c.Response(), c.Request()); err == nil {
		return completeAuth(c, &user, h)
	} else {
		gothic.BeginAuthHandler(c.Response().Writer, r)
	}
	return nil
}

func (h *Handlers) AuthCallback(c echo.Context) error {
	user, err := gothic.CompleteUserAuth(c.Response().Writer, c.Request())
	if err != nil {
		h.logger.Error("OAuth authentication failed", "error", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}
	return completeAuth(c, &user, h)
}

func (h *Handlers) Logout(c echo.Context) error {
	session, _ := h.AuthService.Store.Get(c.Request(), auth.AuthSessionKey)
	user := h.AuthService.GetUser(c)
	if user == nil {
		var err error
		user, err = h.AuthService.GetUserFromSession(session.ID)
		if err != nil {
			h.logger.Warn("Failed to get user info from sessions. ", slog.Any("Error", err))
		}
	}
	if user != nil {
		h.logger.Info("User logging out", "user_id", user.ID, "name", user.Name)
	}

	session.Options.MaxAge = -1
	session.Save(c.Request(), c.Response().Writer)
	gothic.Logout(c.Response().Writer, c.Request())
	return c.Redirect(http.StatusSeeOther, "/")
}

func (h *Handlers) SignIn(c echo.Context) error {
	if loggedIn, err := h.AuthService.LoggedIn(c); err != nil || !loggedIn {
		return defaultRender(c, templates.SignInPage(), nil)
	}
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handlers) CompleteProfileForm(c echo.Context) error {
	user := h.AuthService.GetUser(c)
	if user == nil {
		h.logger.Warn("Unauthorized profile completion form access - no user in context")
		return c.Redirect(http.StatusSeeOther, "/signin")
	}

	h.logger.Debug("Profile completion form accessed", "user_id", user.ID)
	return renderSingle(c, templates.Base(templates.ContentWithCustomNav(templates.SignOutOnlyNav(), templates.CompleteProfileFormWithValues(user.Name, user.Email, ""))))
}

func (h *Handlers) SubmitCompleteProfileForm(c echo.Context) error {
	user := h.AuthService.GetUser(c)
	if user == nil {
		h.logger.Warn("Unauthorized profile completion form submission - no user in context")
		return c.Redirect(http.StatusSeeOther, "/signin")
	}

	name := c.FormValue("name")
	email := c.FormValue("email")

	if name == "" || email == "" {
		h.logger.Warn("Profile completion failed - name and email required", "user_id", user.ID)
		return renderSingle(c, templates.Base(templates.ContentWithCustomNav(templates.SignOutOnlyNav(), templates.CompleteProfileFormWithValues(user.Name, user.Email, ""))))
	}

	_, err := h.db.Exec(`UPDATE users SET name=?, email=? WHERE id=?`, name, email, user.ID)
	if err != nil {
		h.logger.Error("Failed to update user name/email", "error", err, "user_id", user.ID, "email", email, "name", name)
		return c.String(http.StatusInternalServerError, "Failed to update profile")
	}

	h.logger.Info("User profile completed", "user_id", user.ID, "email", email, "name", name)
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

// Protected Recipe Routes
func (h *Handlers) ListRecipes(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	h.logger.Debug("Listing recipes for user", "user_id", user.ID)

	rows, err := h.db.Query(`
		SELECT id, title, description, cook_time, servings, ingredients, instructions, created_at, photo_url, original_url 
		FROM recipes 
		WHERE user_id = ? 
		ORDER BY created_at DESC
	`, user.ID)
	if err != nil {
		h.logger.Error("Failed to fetch recipes", "error", err, "user_id", user.ID)
		return c.String(http.StatusInternalServerError, "Failed to fetch recipes")
	}
	defer rows.Close()

	recipes := []models.Recipe{}

	for rows.Next() {
		var r models.Recipe
		var description, cookTime, servings, photoURL, originalURL sql.NullString
		var createdAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &createdAt, &photoURL, &originalURL); err != nil {
			h.logger.Error("Failed to parse recipe", "error", err, "user_id", user.ID)
			return c.String(http.StatusInternalServerError, "Failed to parse recipe")
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		r.Servings = nullStringToString(servings)
		r.PhotoURL = nullStringToString(photoURL)
		r.OriginalURL = nullStringToString(originalURL)
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		} else {
			r.CreatedAt = ""
		}
		recipes = append(recipes, r)
	}

	h.logger.Debug("Recipes fetched", "user_id", user.ID, "count", len(recipes))

	return defaultRender(c, templates.RecipesList(recipes), user)
}

func (h *Handlers) CreateRecipe(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	title := c.FormValue("title")
	description := c.FormValue("description")
	cookTime := c.FormValue("cookTime")
	servings := c.FormValue("servings")
	ingredients := c.FormValue("ingredients")
	instructions := c.FormValue("instructions")
	photoUrl := c.FormValue("photoUrl")
	originalUrl := c.FormValue("originalUrl")

	if title == "" {
		return c.String(http.StatusBadRequest, "Title is required")
	}

	id := uuid.New().String()
	_, err := h.db.Exec(`INSERT INTO recipes (id, user_id, title, description, cook_time, servings, ingredients, instructions, photo_url, original_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, user.ID, title, nullIfEmpty(description), nullIfEmpty(cookTime), nullIfEmpty(servings), ingredients, instructions, nullIfEmpty(photoUrl), nullIfEmpty(originalUrl))
	if err != nil {
		h.logger.Error("Failed to create recipe", "error", err, "user_id", user.ID, "title", title)
		return c.String(http.StatusInternalServerError, "Failed to create recipe")
	}

	h.logger.Info("Recipe created", "recipe_id", id, "user_id", user.ID, "title", title)

	if isHtmxReq(c) {
		return h.ListRecipes(c)
	}
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func (h *Handlers) AddRecipeForm(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	return defaultRender(c, templates.AddRecipe(), user)
}

func (h *Handlers) AddRecipeFormFromValues(c echo.Context, recipe *models.Recipe) error {
	user := auth.GetUserFromContext(c)
	return defaultRender(c, templates.AddRecipeFromValues(recipe), user)
}

func (h *Handlers) SearchRecipes(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	query := c.FormValue("query")
	h.logger.Debug("Searching recipes", "user_id", user.ID, "query", query)

	if query == "" {
		return h.ListRecipes(c)
	}

	searchQuery := "%" + query + "%"
	rows, err := h.db.Query(`
		SELECT id, title, description, cook_time, servings, ingredients, instructions, created_at, photo_url, original_url 
		FROM recipes 
		WHERE user_id = ? AND (title LIKE ? OR description LIKE ? OR ingredients LIKE ?)
		ORDER BY created_at DESC
	`, user.ID, searchQuery, searchQuery, searchQuery)
	if err != nil {
		h.logger.Error("Failed to search recipes", "error", err, "user_id", user.ID, "query", query)
		return c.String(http.StatusInternalServerError, "Failed to search recipes")
	}
	defer rows.Close()

	recipes := []models.Recipe{}
	for rows.Next() {
		var r models.Recipe
		var description, cookTime, servings, photoURL, originalURL sql.NullString
		var createdAt sql.NullTime
		err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &createdAt, &photoURL, &originalURL)
		if err != nil {
			h.logger.Error("Failed to scan recipe row", "error", err)
			continue
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		r.Servings = nullStringToString(servings)
		r.PhotoURL = nullStringToString(photoURL)
		r.OriginalURL = nullStringToString(originalURL)
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		} else {
			r.CreatedAt = ""
		}
		recipes = append(recipes, r)
	}

	return defaultRender(c, templates.RecipesList(recipes), user)
}

func (h *Handlers) GetRecipe(c echo.Context) error {
	recipeId := c.Param("id")

	// Validate user access to this recipe
	user, err := h.validateRecipeAccess(c, recipeId)
	if err != nil {
		h.logger.Warn("Recipe access denied", "recipe_id", recipeId, "error", err)
		return c.String(http.StatusNotFound, "Recipe not found")
	}

	var r models.Recipe
	var description, cookTime, servings, photoURL, originalURL sql.NullString
	var createdAt sql.NullTime
	err = h.db.QueryRow(`
		SELECT id, title, description, cook_time, servings, ingredients, instructions, created_at, photo_url, original_url 
		FROM recipes 
		WHERE id = ? AND user_id = ?
	`, recipeId, user.ID).Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &createdAt, &photoURL, &originalURL)

	if err == sql.ErrNoRows {
		h.logger.Warn("Recipe not found", "recipe_id", recipeId, "user_id", user.ID)
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
		h.logger.Error("Failed to fetch recipe", "error", err, "recipe_id", recipeId, "user_id", user.ID)
		return c.String(http.StatusInternalServerError, "Failed to fetch recipe")
	}

	r.Description = nullStringToString(description)
	r.CookTime = nullStringToString(cookTime)
	r.Servings = nullStringToString(servings)
	r.OriginalURL = nullStringToString(originalURL)
	r.PhotoURL = nullStringToString(photoURL)
	if createdAt.Valid {
		r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
	} else {
		r.CreatedAt = ""
	}

	return defaultRender(c, templates.Recipe(&r), user)
}

func (h *Handlers) EditRecipeForm(c echo.Context) error {
	recipeId := c.Param("id")

	// Validate user access to this recipe
	user, err := h.validateRecipeAccess(c, recipeId)
	if err != nil {
		h.logger.Warn("Recipe access denied for edit", "recipe_id", recipeId, "error", err)
		return c.String(http.StatusNotFound, "Recipe not found")
	}

	var r models.Recipe
	var description, cookTime, servings, photoUrl sql.NullString
	var createdAt sql.NullTime
	err = h.db.QueryRow(`
		SELECT id, title, description, cook_time, servings, ingredients, instructions, photo_url, created_at 
		FROM recipes 
		WHERE id = ? AND user_id = ?
	`, recipeId, user.ID).Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &photoUrl, &createdAt)

	if err == sql.ErrNoRows {
		h.logger.Warn("Recipe not found for edit", "recipe_id", recipeId, "user_id", user.ID)
		return c.String(http.StatusNotFound, "Recipe not found")
	} else if err != nil {
		h.logger.Error("Failed to fetch recipe for edit", "error", err, "recipe_id", recipeId, "user_id", user.ID)
		return c.String(http.StatusInternalServerError, "Failed to fetch recipe")
	}

	r.Description = nullStringToString(description)
	r.CookTime = nullStringToString(cookTime)
	r.Servings = nullStringToString(servings)
	r.PhotoURL = nullStringToString(photoUrl)
	if createdAt.Valid {
		r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
	} else {
		r.CreatedAt = ""
	}

	return defaultRender(c, templates.EditRecipe(&r), user)
}

func (h *Handlers) UpdateRecipe(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	id := c.Param("id")
	title := c.FormValue("title")
	description := c.FormValue("description")
	cookTime := c.FormValue("cook_time")
	servings := c.FormValue("servings")
	ingredients := c.FormValue("ingredients")
	instructions := c.FormValue("instructions")
	photoUrl := c.FormValue("photoUrl")

	if title == "" {
		return c.String(http.StatusBadRequest, "Title is required")
	}

	result, err := h.db.Exec(`
		UPDATE recipes 
		SET title = ?, description = ?, cook_time = ?, servings = ?, ingredients = ?, instructions = ?, photo_url = ?
		WHERE id = ? AND user_id = ?
	`, title, nullIfEmpty(description), nullIfEmpty(cookTime), nullIfEmpty(servings), ingredients, instructions, nullIfEmpty(photoUrl), id, user.ID)

	if err != nil {
		h.logger.Error("Failed to update recipe", "error", err, "recipe_id", id, "user_id", user.ID)
		return c.String(http.StatusInternalServerError, "Failed to update recipe")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.logger.Warn("Recipe not found for update", "recipe_id", id, "user_id", user.ID)
		return c.String(http.StatusNotFound, "Recipe not found")
	}

	h.logger.Info("Recipe updated", "recipe_id", id, "user_id", user.ID, "title", title)
	if isHtmxReq(c) {
		return h.GetRecipe(c)
	}
	return c.Redirect(http.StatusSeeOther, "/recipes/"+id)
}

func (h *Handlers) DeleteRecipe(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	id := c.Param("id")

	result, err := h.db.Exec(`DELETE FROM recipes WHERE id = ? AND user_id = ?`, id, user.ID)
	if err != nil {
		h.logger.Error("Failed to delete recipe", "error", err, "recipe_id", id, "user_id", user.ID)
		return c.String(http.StatusInternalServerError, "Failed to delete recipe")
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		h.logger.Warn("Recipe not found for deletion", "recipe_id", id, "user_id", user.ID)
		return c.String(http.StatusNotFound, "Recipe not found")
	}

	h.logger.Info("Recipe deleted", "recipe_id", id, "user_id", user.ID)
	return h.ListRecipes(c)
}

func (h *Handlers) ImportRecipeFromURLForm(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	return defaultRender(c, templates.ImportFromUrlDialog(), user)
}

func (h *Handlers) ImportRecipeFromURLFormSubmit(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	url := c.FormValue("url")

	if url == "" {
		return c.String(http.StatusBadRequest, "URL is required")
	}

	recipe, err := h.importRecipeURL(url)
	if err != nil {
		h.logger.Error("Failed to import recipe from URL", "error", err, "url", url, "user_id", user.ID)
		return c.String(http.StatusInternalServerError, "Failed to import recipe")
	}

	return h.AddRecipeFormFromValues(c, recipe)
}

// Integration Routes
func (h *Handlers) LoginOneTsp(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	h.logger.Info("OneTsp login initiated", "user_id", user.ID)

	// Implementation for OneTsp login
	// This would typically involve redirecting to OneTsp's OAuth or API
	return c.String(http.StatusOK, "OneTsp login functionality not yet implemented")
}

func (h *Handlers) ImportOneTsp(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	h.logger.Info("OneTsp import initiated", "user_id", user.ID)

	// Implementation for OneTsp import
	// This would typically involve fetching recipes from OneTsp's API
	return c.String(http.StatusOK, "OneTsp import functionality not yet implemented")
}

// Helper Functions
func (h *Handlers) validateRecipeAccess(c echo.Context, recipeID string) (*models.User, error) {
	user := h.AuthService.GetUser(c)
	if user == nil {
		return nil, fmt.Errorf("user not authenticated")
	}

	// Check if recipe exists and belongs to user
	var exists bool
	err := h.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM recipes 
			WHERE id = ? AND user_id = ?
		)
	`, recipeID, user.ID).Scan(&exists)

	if err != nil {
		return nil, fmt.Errorf("failed to validate recipe access: %w", err)
	}

	if !exists {
		return nil, fmt.Errorf("recipe not found or access denied")
	}

	return user, nil
}

func completeAuth(c echo.Context, user *goth.User, h *Handlers) error {
	if user.Name == "" {
		user.Name = user.NickName
	}
	if user.Name == "" {
		user.Name = user.FirstName + " " + user.LastName
	}

	h.logger.Debug("Starting completeAuth", "user_id", user.UserID, "name", user.Name, "email", user.Email)

	sessionId, err := h.AuthService.CompleteAuth(user)
	if err != nil {
		h.logger.Error("Failed to complete user auth", "user_id", user.UserID, "error", err)
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	h.logger.Debug("Session created, getting session from store", "session_id", sessionId)

	session, err := h.AuthService.Store.Get(c.Request(), auth.AuthSessionKey)
	if err != nil {
		h.logger.Error("Failed to get session from store", "error", err, "session_id", sessionId)
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	session.Values[auth.SessionIdKey] = sessionId
	err = session.Save(c.Request(), c.Response().Writer)
	if err != nil {
		h.logger.Error("Failed to save session", "error", err, "session_id", sessionId)
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	h.logger.Debug("Session saved successfully", "session_id", sessionId)

	if user.Email == "" || user.Name == "" {
		h.logger.Info("User needs to complete profile", "user_id", user.UserID)
		return c.Redirect(http.StatusSeeOther, "/profile/complete")
	}

	h.logger.Info("User authentication completed", "user_id", user.UserID, "name", user.Name)
	return c.Redirect(http.StatusSeeOther, "/recipes")
}

func isHtmxReq(c echo.Context) bool {
	return c.Request().Header.Get("HX-Request") == "true"
}

func nullIfEmpty(s string) any {
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

// func toString(v interface{}) string {
// 	if s, ok := v.(string); ok {
// 		return s
// 	}
// 	return ""
// }

// Handler for importing a recipe from a URL
func (h *Handlers) importRecipeURL(url string) (*models.Recipe, error) {
	apiURL := "https://www.justtherecipe.com/extractRecipeAtUrl?url=" + url
	h.logger.Info("Fetching recipe from external API", "api_url", apiURL)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		h.logger.Error("Failed to fetch recipe from external API", "error", err, "api_url", apiURL)
		return nil, fmt.Errorf("failed to fetch recipe from external API: %s, Error: %w", apiURL, err)
	}
	defer resp.Body.Close()

	h.logger.Info("External API response", "status", resp.Status, "api_url", apiURL)

	if resp.StatusCode != http.StatusOK {
		h.logger.Error("Recipe API returned error status", "status", resp.Status, "api_url", apiURL, "resp", resp)
		return nil, fmt.Errorf("recipe API returned error status: %s", resp.Status)
	}

	var recipeData struct {
		Name        string `json:"name"`
		Servings    int    `json:"servings"`
		CookTime    int64  `json:"cookTime"`
		PrepTime    int64  `json:"prepTime"`
		TotalTime   int64  `json:"totalTime"`
		Ingredients []struct {
			Name string `json:"name"`
		} `json:"ingredients"`
		Instructions    []map[string]interface{} `json:"instructions"`
		SourceUrl       string                   `json:"sourceUrl"`
		ImageUrls       []string                 `json:"imageUrls"`
		Categories      []string                 `json:"categories"`
		Ctemplatessines []string                 `json:"ctemplatessines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&recipeData); err != nil {
		return nil, fmt.Errorf("failed to parse recipe data: %w", err)
	}

	ingredients := ""
	for i, ing := range recipeData.Ingredients {
		ingredients += ing.Name
		if i < len(recipeData.Ingredients)-1 {
			ingredients += "\n"
		}
	}

	instructions := ""
	for _, instr := range recipeData.Instructions {
		// Flat "text" field
		if text, ok := instr["text"].(string); ok && text != "" {
			if instructions != "" {
				instructions += "\n"
			}
			instructions += text
		}
		// Nested "steps" field
		if stepsRaw, ok := instr["steps"]; ok {
			if stepsSlice, ok := stepsRaw.([]any); ok {
				for _, s := range stepsSlice {
					if stepMap, ok := s.(map[string]any); ok {
						if text, ok := stepMap["text"].(string); ok && text != "" {
							if instructions != "" {
								instructions += "\n"
							}
							instructions += text
						}
					}
				}
			}
		}
	}

	cookTime := ""
	if recipeData.TotalTime > 0 {
		d := time.Duration(recipeData.TotalTime) * time.Microsecond
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60

		if hours > 0 && minutes > 0 {
			cookTime = fmt.Sprintf("%d hr %d min", hours, minutes)
		} else if hours > 0 {
			cookTime = fmt.Sprintf("%d hr", hours)
		} else {
			cookTime = fmt.Sprintf("%d min", minutes)
		}
	}

	servings := ""
	if recipeData.Servings > 0 {
		servings = fmt.Sprintf("%d", recipeData.Servings)
	}

	photoUrl := h.getOGImage(url)

	return &models.Recipe{
		ID:           uuid.NewString(),
		Title:        recipeData.Name,
		Description:  "",
		CookTime:     cookTime,
		Servings:     servings,
		Ingredients:  ingredients,
		Instructions: instructions,
		CreatedAt:    "",
		PhotoURL:     photoUrl,
		OriginalURL:  url,
	}, nil
}

func (h *Handlers) getOGImage(url string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		h.logger.Error("Failed to fetch webpage for OG image", "error", err, "url", url)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.logger.Error("Failed to fetch webpage", "status", resp.Status, "url", url)
		return ""
	}

	// Read the HTML content
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.logger.Error("Failed to read webpage body", "error", err, "url", url)
		return ""
	}

	htmlContent := string(body)

	// Look for Open Graph image meta tags
	ogImageRegex := regexp.MustCompile(`<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']+)["'][^>]*>`)
	if matches := ogImageRegex.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return matches[1]
	}

	// Alternative pattern for og:image (more flexible)
	ogImageRegex2 := regexp.MustCompile(`property=["']og:image["'][^>]*content=["']([^"']+)["']`)
	if matches := ogImageRegex2.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return matches[1]
	}

	// Most comprehensive pattern for og:image (handles different quote styles and attribute orders)
	ogImageRegex3 := regexp.MustCompile(`<meta[^>]*property\s*=\s*["']og:image["'][^>]*content\s*=\s*["']([^"']+)["'][^>]*>`)
	if matches := ogImageRegex3.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return matches[1]
	}

	// Fallback to Twitter Card image
	twitterImageRegex := regexp.MustCompile(`<meta[^>]*name=["']twitter:image["'][^>]*content=["']([^"']+)["'][^>]*>`)
	if matches := twitterImageRegex.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
