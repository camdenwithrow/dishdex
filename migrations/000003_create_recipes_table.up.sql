CREATE TABLE IF NOT EXISTS recipes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NULL,
    cook_time TEXT NULL,
    servings TEXT NULL,
    ingredients TEXT,
    instructions TEXT,
    tags TEXT NULL,
    photo_url TEXT NULL,
    original_url TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
); 