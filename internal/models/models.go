package models

import "time"

type User struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type Recipe struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	CookTime     string `json:"cook_time"`
	Servings     string `json:"serving_size"`
	Ingredients  string `json:"ingredients"`
	Instructions string `json:"instructions"`
	CreatedAt    string `json:"created_at"`
	PhotoURL     string `json:"photo_url"`
	OriginalURL  string `json:"original_url"`
	Tags         string `json:"tags"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsActive  bool      `json:"is_active"`
}
