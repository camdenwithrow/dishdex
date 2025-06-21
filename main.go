package main

import (
	"net/http"

	"github.com/a-h/templ"
	"github.com/camdenwithrow/dishdex/templates"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const PORT = "4444"

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Routes
	h := handler{}
	e.GET("/", h.Home())
	e.GET("/health", h.Health())

	e.Logger.Fatal(e.Start(":" + PORT))
}

type handler struct{}

func (handler) Home() echo.HandlerFunc {
	return func(c echo.Context) error {
		return render(c, templates.Home())
	}
}

func (handler) Health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "healthy",
		})
	}
}

func render(c echo.Context, component templ.Component) error {
	return component.Render(c.Request().Context(), c.Response().Writer)
}
