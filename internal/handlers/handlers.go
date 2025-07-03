package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
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

func renderPage(c echo.Context, page templ.Component) error {
	component := page
	if !isHtmxReq(c) {
		component = templates.Base(page)
	}
	return renderComponent(c, component)
}

func renderComponent(c echo.Context, component templ.Component) error {
	return component.Render(c.Request().Context(), c.Response().Writer)
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
		return renderPage(c, templates.Home())
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
		return renderPage(c, templates.SignInPage())
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
	return renderPage(c, templates.CompleteProfileFormWithValues(user.Name, user.Email, ""))
}

func (h *Handlers) SubmitCompleteProfileForm(c echo.Context) error {
	user := h.AuthService.GetUser(c)
	if user == nil {
		h.logger.Warn("Unauthorized profile completion form submission - no user in context")
		return c.Redirect(http.StatusSeeOther, "/signin")
	}

	name := c.FormValue("name")
	email := c.FormValue("email")

	if name == "" {
		h.logger.Warn("Profile completion failed - name and email required", "user_id", user.ID)
		return renderPage(c, templates.CompleteProfileFormWithValues(user.Name, user.Email, "Name Required"))
	}

	if email == "" {
		h.logger.Warn("Profile completion failed - name and email required", "user_id", user.ID)
		return renderPage(c, templates.CompleteProfileFormWithValues(user.Name, user.Email, "Email Required"))
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
		SELECT id, title, description, cook_time, servings, ingredients, instructions, created_at, photo_url, original_url, tags 
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
		var description, cookTime, servings, photoURL, originalURL, tags sql.NullString
		var createdAt sql.NullTime
		if err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &createdAt, &photoURL, &originalURL, &tags); err != nil {
			h.logger.Error("Failed to parse recipe", "error", err, "user_id", user.ID)
			return c.String(http.StatusInternalServerError, "Failed to parse recipe")
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		r.Servings = nullStringToString(servings)
		r.PhotoURL = nullStringToString(photoURL)
		r.OriginalURL = nullStringToString(originalURL)
		r.Tags = nullStringToString(tags)
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		} else {
			r.CreatedAt = ""
		}
		recipes = append(recipes, r)
	}
	sort.Slice(recipes, func(i, j int) bool {
		return recipes[i].Title < recipes[j].Title
	})

	h.logger.Debug("Recipes fetched", "user_id", user.ID, "count", len(recipes))

	return renderPage(c, templates.RecipesList(user, recipes))
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
	tags := c.FormValue("tags")

	if title == "" {
		return c.String(http.StatusBadRequest, "Title is required")
	}

	id := uuid.New().String()
	_, err := h.db.Exec(`INSERT INTO recipes (id, user_id, title, description, cook_time, servings, ingredients, instructions, photo_url, original_url, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, user.ID, title, nullIfEmpty(description), nullIfEmpty(cookTime), nullIfEmpty(servings), ingredients, instructions, nullIfEmpty(photoUrl), nullIfEmpty(originalUrl), nullIfEmpty(tags))
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
	return renderPage(c, templates.AddRecipe(user))
}

func (h *Handlers) AddRecipeFormFromValues(c echo.Context, recipe *models.Recipe) error {
	user := auth.GetUserFromContext(c)
	return renderPage(c, templates.AddRecipeFromValues(user, recipe))
}

func (h *Handlers) SearchRecipes(c echo.Context) error {
	query := c.FormValue("query")
	if query == "" {
		return h.ListRecipes(c)
	}
	user := auth.GetUserFromContext(c)
	h.logger.Debug("Searching recipes", "user_id", user.ID, "query", query)

	searchQuery := "%" + query + "%"
	rows, err := h.db.Query(`
		SELECT id, title, description, cook_time, servings, ingredients, instructions, created_at, photo_url, original_url, tags 
		FROM recipes 
		WHERE user_id = ? AND (title LIKE ? OR description LIKE ? OR ingredients LIKE ? OR tags LIKE ?)
		ORDER BY created_at DESC
	`, user.ID, searchQuery, searchQuery, searchQuery, searchQuery)
	if err != nil {
		h.logger.Error("Failed to search recipes", "error", err, "user_id", user.ID, "query", query)
		return c.String(http.StatusInternalServerError, "Failed to search recipes")
	}
	defer rows.Close()

	type RankedRecipe struct {
		recipe models.Recipe
		rank   int
	}

	rankedRecipes := []RankedRecipe{}
	for rows.Next() {
		var r models.Recipe
		var description, cookTime, servings, photoURL, originalURL, tags sql.NullString
		var createdAt sql.NullTime
		err := rows.Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &createdAt, &photoURL, &originalURL, &tags)
		if err != nil {
			h.logger.Error("Failed to scan recipe row", "error", err)
			continue
		}
		r.Description = nullStringToString(description)
		r.CookTime = nullStringToString(cookTime)
		r.Servings = nullStringToString(servings)
		r.PhotoURL = nullStringToString(photoURL)
		r.OriginalURL = nullStringToString(originalURL)
		r.Tags = nullStringToString(tags)
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		} else {
			r.CreatedAt = ""
		}
		// recipes = append(recipes, r)
		rank := rankQueryRecipes(&r, query)
		rankedRecipes = append(rankedRecipes, RankedRecipe{r, rank})
	}

	sort.Slice(rankedRecipes, func(i int, j int) bool {
		return rankedRecipes[i].rank > rankedRecipes[j].rank
	})

	recipes := []models.Recipe{}
	for _, rankedRecipe := range rankedRecipes {
		recipes = append(recipes, rankedRecipe.recipe)
	}

	return renderPage(c, templates.RecipesList(user, recipes))
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
	var description, cookTime, servings, photoURL, originalURL, tags sql.NullString
	var createdAt sql.NullTime
	err = h.db.QueryRow(`
		SELECT id, title, description, cook_time, servings, ingredients, instructions, created_at, photo_url, original_url, tags 
		FROM recipes 
		WHERE id = ? AND user_id = ?
	`, recipeId, user.ID).Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &createdAt, &photoURL, &originalURL, &tags)

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
	r.Tags = nullStringToString(tags)
	if createdAt.Valid {
		r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
	} else {
		r.CreatedAt = ""
	}

	return renderPage(c, templates.Recipe(user, &r))
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
	var description, cookTime, servings, photoUrl, tags sql.NullString
	var createdAt sql.NullTime
	err = h.db.QueryRow(`
		SELECT id, title, description, cook_time, servings, ingredients, instructions, photo_url, created_at, tags 
		FROM recipes 
		WHERE id = ? AND user_id = ?
	`, recipeId, user.ID).Scan(&r.ID, &r.Title, &description, &cookTime, &servings, &r.Ingredients, &r.Instructions, &photoUrl, &createdAt, &tags)

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
	r.Tags = nullStringToString(tags)
	if createdAt.Valid {
		r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
	} else {
		r.CreatedAt = ""
	}

	return renderPage(c, templates.EditRecipe(user, &r))
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
	tags := c.FormValue("tags")

	if title == "" {
		return c.String(http.StatusBadRequest, "Title is required")
	}

	result, err := h.db.Exec(`
		UPDATE recipes 
		SET title = ?, description = ?, cook_time = ?, servings = ?, ingredients = ?, instructions = ?, photo_url = ?, tags = ?
		WHERE id = ? AND user_id = ?
	`, title, nullIfEmpty(description), nullIfEmpty(cookTime), nullIfEmpty(servings), ingredients, instructions, nullIfEmpty(photoUrl), nullIfEmpty(tags), id, user.ID)

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
	return renderComponent(c, templates.ImportFromUrlDialog())
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
func (h *Handlers) LoginOneTspForm(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	h.logger.Info("OneTsp login initiated", "user_id", user.ID)

	return renderComponent(c, templates.OneTspLoginDialog())
}

func (h *Handlers) LoginOneTspFormSubmit(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	email := c.FormValue("email")
	password := c.FormValue("password")

	h.logger.Info("OneTsp login form submitted", "user_id", user.ID, "email", email)

	if email == "" || password == "" {
		h.logger.Warn("OneTsp login failed - missing credentials", "user_id", user.ID)
		return c.String(http.StatusBadRequest, "Email and password are required")
	}
	apiUrl := "https://dishdex-import-production.up.railway.app/api/login/onetsp"

	payload := map[string]string{
		"username": email,
		"password": password,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		h.logger.Error("Failed to marshal payload", "error", err)
		return c.String(http.StatusInternalServerError, "Failed to marshal payload")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", apiUrl, bytes.NewReader(jsonPayload))
	if err != nil {
		h.logger.Error("Failed to create request", "error", err)
		return c.String(http.StatusInternalServerError, "Failed to create request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		h.logger.Error("Failed to send request", "error", err)
		return c.String(http.StatusInternalServerError, "Failed to send request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.logger.Error("Failed to login", "status", resp.StatusCode, "body", resp.Body)
		return c.String(http.StatusInternalServerError, "Failed to login")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.logger.Error("Failed to read response body", "error", err)
		return c.String(http.StatusInternalServerError, "Failed to read response body")
	}

	h.logger.Info("OneTsp login successful", "user_id", user.ID, "email", email)

	var response struct {
		Token string `json:"token"`
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		h.logger.Error("Failed to unmarshal response", "error", err)
		return c.String(http.StatusInternalServerError, "Failed to unmarshal response")
	}
	return renderComponent(c, templates.OneTspImportDialog(response.Token))
}

func (h *Handlers) ImportOneTsp(c echo.Context) error {
	user := auth.GetUserFromContext(c)
	token := c.FormValue("token")

	if token == "" {
		h.logger.Error("OneTsp import failed - no token provided", "user_id", user.ID)
		return renderPage(c, templates.ErrorMessage("Import failed: No token provided"))
	}

	h.logger.Info("OneTsp import initiated", "user_id", user.ID)

	// Make POST request to external API
	apiURL := "https://dishdex-import-production.up.railway.app/api/import/onetsp"

	// Prepare request body
	requestBody := map[string]string{
		"token": token,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		h.logger.Error("Failed to marshal request body", "error", err, "user_id", user.ID)
		return renderPage(c, templates.ErrorMessage("Import failed: Invalid request"))
	}

	// Create HTTP client with timeout
	client := &http.Client{Timeout: 30 * time.Second}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		h.logger.Error("Failed to create request", "error", err, "user_id", user.ID)
		return renderPage(c, templates.ErrorMessage("Import failed: Could not create request"))
	}

	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		h.logger.Error("Failed to make request to OneTsp API", "error", err, "user_id", user.ID, "api_url", apiURL)
		return renderPage(c, templates.ErrorMessage("Import failed: Could not connect to OneTsp"))
	}
	defer resp.Body.Close()

	h.logger.Info("OneTsp API response", "status", resp.Status, "user_id", user.ID)

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		h.logger.Error("OneTsp API returned error status", "status", resp.Status, "body", string(bodyBytes), "user_id", user.ID)
		return renderPage(c, templates.ErrorMessage("Import failed: OneTsp API returned error"))
	}

	// Parse response
	var response struct {
		Recipes []struct {
			URL          string   `json:"url"`
			Title        string   `json:"title"`
			Ingredients  []string `json:"ingredients"`
			Instructions []string `json:"instructions"`
			RecipeURL    *string  `json:"recipeUrl"`
			Tags         []string `json:"tags"`
			Cooktime     string   `json:"cooktime"`
		} `json:"recipes"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		h.logger.Error("Failed to parse OneTsp API response", "error", err, "user_id", user.ID)
		return renderPage(c, templates.ErrorMessage("Import failed: Invalid response from OneTsp"))
	}

	// Save recipes to database
	importedCount := 0
	for _, recipeData := range response.Recipes {
		recipeID := uuid.NewString()

		// Convert ingredients array to string
		ingredients := ""
		for i, ingredient := range recipeData.Ingredients {
			ingredients += ingredient
			if i < len(recipeData.Ingredients)-1 {
				ingredients += "\n"
			}
		}

		// Convert instructions array to string
		instructions := ""
		for i, instruction := range recipeData.Instructions {
			instructions += instruction
			if i < len(recipeData.Instructions)-1 {
				instructions += "\n"
			}
		}

		// Convert tags array to string
		tags := ""
		for i, tag := range recipeData.Tags {
			tags += tag
			if i < len(recipeData.Tags)-1 {
				tags += ", "
			}
		}

		// Handle recipeUrl (can be null)
		originalURL := ""
		if recipeData.RecipeURL != nil {
			originalURL = *recipeData.RecipeURL
		}

		// Get OG image from RecipeURL if available
		photoURL := ""
		if originalURL != "" {
			photoURL = h.getOGImage(originalURL)
		}

		// Try to import from URL if we have one, to get better data
		var importedRecipe *models.Recipe
		if originalURL != "" {
			h.logger.Info("Attempting to import recipe from URL to enhance OneTsp data",
				"user_id", user.ID, "recipe_title", recipeData.Title, "url", originalURL)

			var err error
			importedRecipe, err = h.importRecipeURL(originalURL)
			if err != nil {
				h.logger.Error("Failed to import recipe from URL, using OneTsp data only",
					"error", err, "user_id", user.ID, "recipe_title", recipeData.Title, "url", originalURL)
			} else {
				h.logger.Info("Successfully imported recipe from URL to enhance OneTsp data",
					"user_id", user.ID, "recipe_title", recipeData.Title, "url", originalURL)
			}
		}

		// Prepare recipe data, prioritizing imported data when available
		recipeTitle := recipeData.Title
		cookTime := recipeData.Cooktime
		servings := ""

		if importedRecipe != nil {
			// Use imported recipe data to enhance OneTsp data
			if importedRecipe.Title != "" {
				recipeTitle = importedRecipe.Title
			}
			if importedRecipe.CookTime != "" {
				cookTime = importedRecipe.CookTime
			}
			servings = importedRecipe.Servings
			if len(importedRecipe.Ingredients) > 0 {
				ingredients = importedRecipe.Ingredients
			}
			if len(importedRecipe.Instructions) > 0 {
				instructions = importedRecipe.Instructions
			}
			if photoURL == "" {
				photoURL = importedRecipe.PhotoURL
			}
		}

		_, err := h.db.Exec(`
			INSERT INTO recipes (id, user_id, title, description, cook_time, servings, ingredients, instructions, photo_url, original_url, tags, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, recipeID, user.ID, recipeTitle, "", cookTime, servings,
			ingredients, instructions, photoURL, originalURL, tags,
			time.Now().UTC())

		if err != nil {
			h.logger.Error("Failed to save imported recipe", "error", err, "user_id", user.ID, "recipe_title", recipeData.Title)
			continue
		}

		importedCount++
		h.logger.Info("Successfully imported recipe", "user_id", user.ID, "recipe_id", recipeID, "recipe_title", recipeData.Title)
	}

	h.logger.Info("OneTsp import completed", "user_id", user.ID, "imported_count", importedCount, "total_recipes", len(response.Recipes))

	// Redirect to recipes page to show imported recipes
	return h.ListRecipes(c)
}

func (h *Handlers) AccountPage(c echo.Context) error {
	user := h.AuthService.GetUser(c)
	if user == nil {
		h.logger.Warn("Unauthorized account page access - no user in context")
		return c.Redirect(http.StatusSeeOther, "/signin")
	}
	return renderPage(c, templates.AccountPage(user))
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
	if user.Name == "" && user.NickName != "" {
		user.Name = user.NickName
	}
	if user.Name == "" && user.FirstName != "" && user.LastName != "" {
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

	userFromContext := h.AuthService.GetUser(c)
	userName := ""
	userEmail := ""
	if userFromContext != nil {
		userName = userFromContext.Name
		userEmail = userFromContext.Email
	} else {
		userName = user.Name
		userEmail = user.Email
	}

	if userEmail == "" || userName == "" {
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
		Instructions []map[string]interface{} `json:"instructions"`
		SourceUrl    string                   `json:"sourceUrl"`
		ImageUrls    []string                 `json:"imageUrls"`
		Categories   []string                 `json:"categories"`
		Cuisines     []string                 `json:"cuisines"`
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

func rankQueryRecipes(recipe *models.Recipe, query string) int {
	rank := 0
	query = strings.ToLower(query)
	title := strings.ToLower(recipe.Title)
	tags := strings.ToLower(recipe.Tags)
	description := strings.ToLower(recipe.Description)
	ingredients := strings.ToLower(recipe.Ingredients)

	if strings.Contains(title, query) {
		return rankValue(title, query, rank+80)
	}

	if strings.Contains(tags, query) {
		return rankValue(tags, query, rank+60)
	}

	if strings.Contains(description, query) {
		return rankValue(description, query, rank+40)
	}

	if strings.Contains(ingredients, query) {
		return rankValue(ingredients, query, rank+20)
	}
	return rank
}

func rankValue(value string, query string, initial int) int {
	rank := initial

	if strings.HasPrefix(value, query) {
		return rank + 9
	}

	splitTitle := strings.SplitSeq(value, " ")
	for word := range splitTitle {
		if word == query {
			rank = rank + 1
		}
	}
	return rank
}
