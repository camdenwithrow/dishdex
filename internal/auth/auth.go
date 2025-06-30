package auth

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/camdenwithrow/dishdex/internal/config"
	l "github.com/camdenwithrow/dishdex/internal/logger"
	"github.com/camdenwithrow/dishdex/internal/models"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

const (
	AuthSessionKey = "auth_session"
	SessionIdKey   = "sessionId"
	UserKey        = "user"
	UserIdKey      = "userId"
	LoggedInKey    = "loggedIn"
)

type AuthService struct {
	Store  *sessions.CookieStore
	db     *sql.DB
	cfg    *config.Config
	logger *l.Logger
}

func NewAuthService(cfg *config.Config, db *sql.DB, logger *l.Logger) *AuthService {
	sessionSecret := cfg.SessionSecret
	if sessionSecret == "" {
		sessionSecret = "dev_secret_key"
		logger.Warn("Using default session secret - not recommended for production")
	}

	store := sessions.NewCookieStore([]byte(sessionSecret))
	store.MaxAge(86400 * 30) // 30 days
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = cfg.Env == "production" // HTTPS only in production
	store.Options.SameSite = http.SameSiteLaxMode
	gothic.Store = store
	return &AuthService{store, db, cfg, logger}
}

func (a *AuthService) SetupOAuth() {
	// Setup OAuth providers with proper callback URLs
	if a.cfg.GitHubClientID != "" && a.cfg.GitHubClientSecret != "" {
		githubCallback := a.cfg.BaseURL + "/auth/github/callback"
		goth.UseProviders(
			github.New(a.cfg.GitHubClientID, a.cfg.GitHubClientSecret, githubCallback),
		)
		a.logger.Info("GitHub OAuth provider configured", "callback", githubCallback)
	}

	if a.cfg.GoogleClientID != "" && a.cfg.GoogleClientSecret != "" {
		googleCallback := a.cfg.BaseURL + "/auth/google/callback"
		goth.UseProviders(
			google.New(a.cfg.GoogleClientID, a.cfg.GoogleClientSecret, googleCallback),
		)
		a.logger.Info("Google OAuth provider configured", "callback", googleCallback)
	}
}

func (a *AuthService) AuthSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		session, err := a.GetSession(c)
		if err != nil || session == nil {
			c.Set(LoggedInKey, false)
			return next(c)
		}

		c.Set(LoggedInKey, true)
		if user, err := a.GetUserFromSession(session.Values[SessionIdKey].(string)); err == nil {
			c.Set(UserKey, user)
			a.logger.Debug("User authenticated", "user_id", user.ID, "name", user.Name)
		}
		return next(c)
	}
}

func (a *AuthService) ProtectedRouteMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		loggedIn, _ := c.Get("loggedIn").(bool)
		if !loggedIn {
			a.logger.Debug("Login required - redirecting to home")
			return c.Redirect(http.StatusSeeOther, "/")
		}
		user := c.Get(UserKey).(*models.User)
		if user.Name == "" || user.Email == "" {
			return c.Redirect(http.StatusSeeOther, "/profile/complete")
		}
		return next(c)
	}
}

func (a *AuthService) LoggedIn(c echo.Context) (bool, error) {
	if loggedIn, ok := c.Get(LoggedInKey).(bool); ok && loggedIn {
		return true, nil
	}

	session, err := a.Store.Get(c.Request(), AuthSessionKey)
	if err != nil {
		return false, err
	}

	sessionID, ok := session.Values[SessionIdKey].(string)
	if !ok || sessionID == "" {
		return false, nil
	}

	// Verify session exists and is active in database
	var exists bool
	err = a.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM sessions 
			WHERE id = ? AND is_active = 1 AND expires_at > ?
		)
	`, sessionID, time.Now()).Scan(&exists)

	if err != nil || !exists {
		a.logger.Warn("Failed to get session from db", "error", err)
		return false, err
	}

	return true, nil
}

func (a *AuthService) GetSession(c echo.Context) (*sessions.Session, error) {
	session, err := a.Store.Get(c.Request(), AuthSessionKey)
	if err != nil {
		a.logger.Debug("Failed to get session from store", "error", err)
		return nil, err
	}

	sessionID, ok := session.Values[SessionIdKey].(string)
	if !ok || sessionID == "" {
		return nil, err
	}

	var exists bool
	err = a.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM sessions 
			WHERE id = ? AND is_active = 1 AND expires_at > ?
		)
	`, sessionID, time.Now()).Scan(&exists)

	if err != nil || !exists {
		a.logger.Debug("Session not found in database or expired", "session_id", sessionID, "error", err)
		return nil, err
	}

	return session, nil
}

func (a *AuthService) CreateSession(userID string) (string, error) {
	sessionID := fmt.Sprintf("sess_%d", time.Now().UnixNano())
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days

	a.logger.Debug("Creating session", "session_id", sessionID, "user_id", userID, "expires_at", expiresAt)

	_, err := a.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at, is_active) 
		VALUES (?, ?, ?, 1)
	`, sessionID, userID, expiresAt)

	if err != nil {
		a.logger.Error("Failed to create session", "error", err, "session_id", sessionID, "user_id", userID)
		return "", fmt.Errorf("failed to create session in database: %w", err)
	}

	a.logger.Debug("Session created successfully", "session_id", sessionID, "user_id", userID)
	return sessionID, nil
}

func (a *AuthService) GetUserFromSession(sessionID string) (*models.User, error) {
	var user models.User
	err := a.db.QueryRow(`
		SELECT u.id, u.name, u.email, u.avatar_url 
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = ? AND s.is_active = 1 AND s.expires_at > ?
	`, sessionID, time.Now()).Scan(&user.ID, &user.Name, &user.Email, &user.AvatarURL)

	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *AuthService) InvalidateSession(sessionID string) error {
	_, err := a.db.Exec(`UPDATE sessions SET is_active = 0 WHERE id = ?`, sessionID)
	return err
}

func (a *AuthService) CleanupExpiredSessions() error {
	result, err := a.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	a.logger.Info("Cleaned up expired sessions", "count", rowsAffected)
	return nil
}

func (a *AuthService) StartSessionCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			if err := a.CleanupExpiredSessions(); err != nil {
				a.logger.Error("Session cleanup failed", "error", err)
			}
		}
	}()
}

func (a *AuthService) CompleteAuth(user *goth.User) (string, error) {
	a.logger.Info("OAuth authentication successful",
		"provider", user.Provider,
		"user_id", user.UserID,
		"name", user.Name,
		"email", user.Email,
	)

	// Attempt to upsert user with retry logic
	a.logger.Info("Attempting to upsert user", "user_id", user.UserID, "name", user.Name, "email", user.Email)
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		_, err = a.db.Exec(`INSERT OR REPLACE INTO users (id, name, email, avatar_url) VALUES (?, ?, ?, ?)`,
			user.UserID, user.Name, user.Email, user.AvatarURL)
		if err == nil {
			break
		}
		a.logger.Warn("Failed to upsert user, retrying", "attempt", attempt, "error", err, "user_id", user.UserID)
		if attempt < 3 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	if err != nil {
		a.logger.Error("Failed to upsert user after retries", "error", err, "user_id", user.UserID)
		return "", fmt.Errorf("failed to upsert user: %w", err)
	} else {
		a.logger.Info("User upserted successfully", "user_id", user.UserID, "name", user.Name)
	}

	// Attempt to create session with retry logic
	a.logger.Info("Creating session for user", "user_id", user.UserID)
	var sessionID string
	for attempt := 1; attempt <= 3; attempt++ {
		sessionID, err = a.CreateSession(user.UserID)
		if err == nil {
			break
		}
		a.logger.Warn("Failed to create session, retrying", "attempt", attempt, "error", err, "user_id", user.UserID)
		if attempt < 3 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	if err != nil {
		a.logger.Error("Failed to create session after retries", "error", err, "user_id", user.UserID)
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	a.logger.Info("Auth completion successful", "user_id", user.UserID, "session_id", sessionID)
	return sessionID, nil
}

func GetUserFromContext(c echo.Context) *models.User {
	if c == nil {
		return nil
	}

	// Try to get user from context
	userInterface := c.Get(UserKey)
	if userInterface == nil {
		return nil
	}

	// Type assertion with safety check
	user, ok := userInterface.(*models.User)
	if !ok {
		// Try to get as value type and convert to pointer
		if userValue, ok := userInterface.(models.User); ok {
			return &userValue
		}
		return nil
	}

	// Validate user data
	if user == nil || user.ID == "" {
		return nil
	}

	return user
}

// GetUserWithFallback attempts to get user from context first, then falls back to session lookup
// This is useful for cases where the middleware might not have run or the context was cleared
func (a *AuthService) GetUserWithFallback(c echo.Context) (*models.User, error) {
	// Try the simple GetUserFromContext first
	if user := GetUserFromContext(c); user != nil {
		return user, nil
	}

	// Fallback to session lookup
	session, err := a.GetSession(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if session == nil {
		return nil, fmt.Errorf("no valid session found")
	}

	sessionID, ok := session.Values[SessionIdKey].(string)
	if !ok || sessionID == "" {
		return nil, fmt.Errorf("no session ID found")
	}

	user, err := a.GetUserFromSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from session: %w", err)
	}

	return user, nil
}

// GetUser is a wrapper that handles errors gracefully and returns nil on any error
func (a *AuthService) GetUser(c echo.Context) *models.User {
	user, err := a.GetUserWithFallback(c)
	if err != nil {
		a.logger.Debug("Failed to get user safely", "error", err)
		return nil
	}
	return user
}

// ValidateUserAccess checks if the current user has access to a specific resource
// This is useful for additional security checks beyond basic authentication
func (a *AuthService) ValidateUserAccess(c echo.Context, resourceOwnerID string) bool {
	user := GetUserFromContext(c)
	if user == nil {
		return false
	}

	// Check if user owns the resource
	if user.ID == resourceOwnerID {
		return true
	}

	// Add additional permission checks here if needed
	// For example, admin roles, shared resources, etc.

	return false
}

// IsUserAuthenticated provides a simple boolean check for authentication status
func (a *AuthService) IsUserAuthenticated(c echo.Context) bool {
	user := GetUserFromContext(c)
	return user != nil && user.ID != ""
}

// GetUserID safely extracts the user ID, returning empty string if not authenticated
func (a *AuthService) GetUserID(c echo.Context) string {
	user := GetUserFromContext(c)
	if user == nil {
		return ""
	}
	return user.ID
}
