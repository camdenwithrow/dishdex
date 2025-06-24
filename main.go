package main

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/camdenwithrow/dishdex/ui"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

type handler struct {
	db *sql.DB
}

func main() {
	db, err := initDB()
	if err != nil {
		log.Fatal("Failed to connect to db ", err)
	}
	defer db.Close()

	handler := &handler{db: db}

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.Static("/static", "ui/static")

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
	if isHtmxReq(c) {
		return render(c, ui.Home())
	}
	return render(c, ui.Base(ui.Home(), false))
}

func (h *handler) createRecipe(c echo.Context) error {
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

func (h *handler) listRecipes(c echo.Context) error {
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

	if isHtmxReq(c) {
		return render(c, ui.RecipesList(tRecipes, []string{}, []string{}))
	}

	return render(c, ui.Base(ui.RecipesList(tRecipes, []string{}, []string{}), true))
}

func (h *handler) getRecipe(c echo.Context) error {
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

	if isHtmxReq(c) {
		return render(c, ui.ShowRecipe(recipeDetail))
	}
	return render(c, ui.Base(ui.ShowRecipe(recipeDetail), true))
}

func (h *handler) updateRecipe(c echo.Context) error {
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

func (h *handler) deleteRecipe(c echo.Context) error {
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

func (h *handler) searchRecipes(c echo.Context) error {
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

	if isHtmxReq(c) {
		return render(c, ui.RecipesList(tRecipes, []string{}, []string{}))
	}

	return render(c, ui.Base(ui.RecipesList(tRecipes, []string{}, []string{}), true))
}

func (h *handler) showAddRecipeForm(c echo.Context) error {
	if isHtmxReq(c) {
		return render(c, ui.AddRecipe())
	}
	return render(c, ui.Base(ui.AddRecipe(), true))
}

func (h *handler) showEditRecipeForm(c echo.Context) error {
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

	if isHtmxReq(c) {
		return render(c, ui.EditRecipe(recipeDetail))
	}
	return render(c, ui.Base(ui.EditRecipe(recipeDetail), true))
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
