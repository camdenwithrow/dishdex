package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/camdenwithrow/dishdex/internal/config"
	"github.com/labstack/echo/v4"
)

type Logger struct {
	*slog.Logger
}

func SetupLogger(cfg *config.Config) *Logger {
	logLevel := slog.LevelInfo
	if levelStr := cfg.LogLevel; levelStr != "" {
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
	if cfg.Env == "production" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = &DevHandler{
			opts: opts,
		}
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	return &Logger{logger}
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

func (l *Logger) RequestLoggerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()

		req := c.Request()
		path := req.URL.Path
		method := req.Method

		isHtmx := c.Request().Header.Get("HX-Request") == "true"

		// Only log non-static requests and non-health checks
		if !strings.HasPrefix(path, "/static") && path != "/health" {
			l.Debug("Request started", "method", method, "path", path, "htmx", isHtmx)
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

			l.Log(context.Background(), logLevel, "Request completed",
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

func DisableEchoDefaultLogger(e *echo.Echo) {
	e.Logger.SetOutput(io.Discard)
	e.Logger.SetLevel(0) // Disable all Echo logging levels
}
