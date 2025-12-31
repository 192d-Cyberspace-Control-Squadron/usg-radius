-- PostgreSQL schema for USG RADIUS authentication
-- This schema provides a basic structure for storing user credentials
-- and RADIUS attributes in a PostgreSQL database.

-- Create the database (run as superuser)
-- CREATE DATABASE radius;
-- CREATE USER radius WITH PASSWORD 'changeme';
-- GRANT ALL PRIVILEGES ON DATABASE radius TO radius;

-- Connect to the radius database before running the following:

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    notes TEXT
);

-- User attributes table (for additional RADIUS attributes)
CREATE TABLE IF NOT EXISTS user_attributes (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    attribute_type INTEGER NOT NULL,
    attribute_value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(username, attribute_type, attribute_value)
);

-- Authentication attempts log (optional, for auditing)
CREATE TABLE IF NOT EXISTS auth_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    source_ip INET NOT NULL,
    success BOOLEAN NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    nas_identifier VARCHAR(255),
    nas_ip_address INET
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);
CREATE INDEX IF NOT EXISTS idx_user_attributes_username ON user_attributes(username);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_username ON auth_attempts(username);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_timestamp ON auth_attempts(timestamp);

-- Example: Insert a test user with bcrypt password hash
-- Password: "password123"
-- You can generate bcrypt hashes using:
-- - Python: import bcrypt; print(bcrypt.hashpw(b'password123', bcrypt.gensalt()).decode())
-- - Node.js: bcrypt.hash('password123', 10)
-- - Online tools (not recommended for production)

INSERT INTO users (username, password_hash, enabled) VALUES
    ('testuser', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqJxm1O3yG', true)
ON CONFLICT (username) DO NOTHING;

-- Example: Add RADIUS attributes for a user
-- Common RADIUS attribute types:
--   1  = User-Name
--   6  = Service-Type
--   7  = Framed-Protocol
--   8  = Framed-IP-Address
--   11 = Filter-Id
--   25 = Class
--   27 = Session-Timeout
--   28 = Idle-Timeout

INSERT INTO user_attributes (username, attribute_type, attribute_value) VALUES
    ('testuser', 6, '2'),  -- Service-Type: Framed
    ('testuser', 27, '3600')  -- Session-Timeout: 1 hour
ON CONFLICT (username, attribute_type, attribute_value) DO NOTHING;

-- Function to update the updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- View for user summary (useful for admin interfaces)
CREATE OR REPLACE VIEW user_summary AS
SELECT
    u.username,
    u.enabled,
    u.created_at,
    u.updated_at,
    u.last_login,
    COUNT(ua.id) as attribute_count,
    COALESCE(
        (SELECT COUNT(*) FROM auth_attempts WHERE username = u.username AND success = true),
        0
    ) as successful_auths,
    COALESCE(
        (SELECT COUNT(*) FROM auth_attempts WHERE username = u.username AND success = false),
        0
    ) as failed_auths
FROM users u
LEFT JOIN user_attributes ua ON u.username = ua.username
GROUP BY u.username, u.enabled, u.created_at, u.updated_at, u.last_login;

-- Grant permissions to radius user
GRANT SELECT, INSERT, UPDATE ON users TO radius;
GRANT SELECT ON user_attributes TO radius;
GRANT INSERT ON auth_attempts TO radius;
GRANT SELECT ON user_summary TO radius;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE user_attributes_id_seq TO radius;
GRANT USAGE, SELECT ON SEQUENCE auth_attempts_id_seq TO radius;
