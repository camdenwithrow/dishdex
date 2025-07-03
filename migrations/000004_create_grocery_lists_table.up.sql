CREATE TABLE grocery_lists (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE grocery_list_items (
    id TEXT PRIMARY KEY,
    grocery_list_id TEXT NOT NULL,
    name TEXT NOT NULL,
    checked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (grocery_list_id) REFERENCES grocery_lists(id) ON DELETE CASCADE
); 