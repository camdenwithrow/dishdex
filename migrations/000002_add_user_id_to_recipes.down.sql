-- Remove foreign key constraint if it exists
-- ALTER TABLE recipes DROP CONSTRAINT IF EXISTS fk_recipes_user_id;

-- Remove user_id column from recipes table
ALTER TABLE recipes DROP COLUMN user_id; 