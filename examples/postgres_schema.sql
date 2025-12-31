-- PostgreSQL database schema example for RADIUS server
--
-- This schema provides:
-- 1. User authentication with bcrypt password hashing
-- 2. RADIUS attribute storage per user
-- 3. Optimized indexes for fast lookups
--
-- Performance considerations:
-- - username column has UNIQUE index for O(log n) lookups
-- - user_attributes has composite index on (username, attribute_type)
-- - enabled column allows soft-delete without removing user data

-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE
);

-- Index for fast username lookups (automatically created by UNIQUE constraint)
-- CREATE UNIQUE INDEX idx_users_username ON users(username);

-- Index for filtering enabled users (if you filter by enabled in queries)
CREATE INDEX idx_users_enabled ON users(enabled) WHERE enabled = true;

-- User RADIUS attributes table
CREATE TABLE IF NOT EXISTS user_attributes (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    attribute_type INTEGER NOT NULL,
    attribute_value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key to users table
    CONSTRAINT fk_user_attributes_username
        FOREIGN KEY (username)
        REFERENCES users(username)
        ON DELETE CASCADE
);

-- Composite index for fast attribute lookups by username
-- This index enables efficient queries like:
-- SELECT attribute_type, attribute_value FROM user_attributes WHERE username = $1
CREATE INDEX idx_user_attributes_username ON user_attributes(username, attribute_type);

-- Example: Insert a test user with bcrypt-hashed password
-- Password is "password123" hashed with bcrypt cost 12
INSERT INTO users (username, password_hash, enabled)
VALUES (
    'testuser',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyMK8S7MhPYO',
    true
) ON CONFLICT (username) DO NOTHING;

-- Example: Insert RADIUS attributes for the test user
INSERT INTO user_attributes (username, attribute_type, attribute_value)
VALUES
    ('testuser', 25, '192.168.1.100'),  -- Class attribute (example)
    ('testuser', 11, '1h'),              -- Session-Timeout (example)
    ('testuser', 27, '300')              -- Session-Timeout in seconds (example)
ON CONFLICT DO NOTHING;

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at on user changes
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Query performance analysis queries
-- Use these to verify your indexes are being used:

-- EXPLAIN ANALYZE for user lookup query
-- EXPLAIN ANALYZE
-- SELECT username, password_hash
-- FROM users
-- WHERE username = 'testuser' AND enabled = true;
-- Expected: Index Scan using idx_users_username

-- EXPLAIN ANALYZE for user attributes query
-- EXPLAIN ANALYZE
-- SELECT attribute_type, attribute_value
-- FROM user_attributes
-- WHERE username = 'testuser';
-- Expected: Index Scan using idx_user_attributes_username

-- Maintenance queries

-- Update user password (using bcrypt hash)
-- UPDATE users
-- SET password_hash = '$2b$12$NEW_HASH_HERE'
-- WHERE username = 'testuser';

-- Disable a user without deleting their data
-- UPDATE users
-- SET enabled = false
-- WHERE username = 'testuser';

-- Clean up old users (soft-deleted for more than 90 days)
-- DELETE FROM users
-- WHERE enabled = false
--   AND updated_at < CURRENT_TIMESTAMP - INTERVAL '90 days';

-- View statistics
-- SELECT
--     COUNT(*) as total_users,
--     COUNT(*) FILTER (WHERE enabled = true) as enabled_users,
--     COUNT(*) FILTER (WHERE enabled = false) as disabled_users,
--     COUNT(*) FILTER (WHERE last_login > CURRENT_TIMESTAMP - INTERVAL '7 days') as active_last_week
-- FROM users;
