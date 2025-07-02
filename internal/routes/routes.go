package routes

import (
	"net/http"

	"github.com/camdenwithrow/dishdex/internal/auth"
	"github.com/camdenwithrow/dishdex/internal/handlers"
	"github.com/camdenwithrow/dishdex/internal/logger"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func SetupRoutes(e *echo.Echo, h *handlers.Handlers, a *auth.AuthService, log *logger.Logger) {
	// Middleware
	e.Use(log.RequestLoggerMiddleware)
	e.Use(middleware.Recover())

	// CORS configuration
	corsConfig := middleware.CORSConfig{
		AllowOrigins: []string{"*"}, // Configure appropriately for production
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}
	e.Use(middleware.CORSWithConfig(corsConfig))

	e.Use(a.AuthSessionMiddleware)
	e.Use(middleware.Secure())
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20))) // 20 requests per second

	e.Static("/static", "static")

	// Main Routes
	e.GET("/", h.Home)
	e.GET("/health", h.Health)

	// Auth Routes
	e.GET("/auth/:provider", h.BeginAuth)
	e.GET("/auth/:provider/callback", h.AuthCallback)
	e.POST("/logout", h.Logout)
	e.GET("/signin", h.SignIn)
	e.GET("/profile/complete", h.CompleteProfileForm)
	e.POST("/profile/complete", h.SubmitCompleteProfileForm)

	// Protected Routes
	e.GET("/account", h.AccountPage, a.ProtectedRouteMiddleware)

	recipes := e.Group("/recipes", a.ProtectedRouteMiddleware)
	recipes.GET("", h.ListRecipes)
	recipes.POST("", h.CreateRecipe)
	recipes.GET("/new", h.AddRecipeForm)
	recipes.POST("/search", h.SearchRecipes)
	recipes.GET("/:id", h.GetRecipe)
	recipes.GET("/:id/edit", h.EditRecipeForm)
	recipes.PUT("/:id", h.UpdateRecipe)
	recipes.DELETE("/:id", h.DeleteRecipe)
	recipes.GET("/new/url", h.ImportRecipeFromURLForm)
	recipes.POST("/new/url", h.ImportRecipeFromURLFormSubmit)

	// Integration Routes
	recipes.GET("/onetsp/login", h.LoginOneTspForm)
	recipes.POST("/onetsp/login", h.LoginOneTspFormSubmit)
	recipes.POST("/onetsp/import", h.ImportOneTsp)
}
