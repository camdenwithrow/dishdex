-- Add user_id column to recipes table
ALTER TABLE recipes ADD COLUMN user_id TEXT;

-- Create a default user for existing recipes (optional - you may want to handle this differently)
-- INSERT OR IGNORE INTO users (id, name, email, avatar_url) VALUES ('default-user', 'Default User', 'default@example.com', '');

-- Update existing recipes to have a user_id (you may want to customize this)
-- UPDATE recipes SET user_id = 'default-user' WHERE user_id IS NULL;

-- Make user_id NOT NULL (uncomment after handling existing data)
-- ALTER TABLE recipes ALTER COLUMN user_id SET NOT NULL;

-- Add foreign key constraint (uncomment after handling existing data)
-- ALTER TABLE recipes ADD CONSTRAINT fk_recipes_user_id FOREIGN KEY (user_id) REFERENCES users(id); 