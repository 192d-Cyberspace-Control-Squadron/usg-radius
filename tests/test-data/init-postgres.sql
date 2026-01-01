-- PostgreSQL Test Data Initialization
-- This file contains test data for PostgreSQL integration tests

-- Create users table if not exists
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on username for fast lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Create user_attributes table if not exists
CREATE TABLE IF NOT EXISTS user_attributes (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    attribute_type VARCHAR(100) NOT NULL,
    attribute_value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Create index for user attributes lookups
CREATE INDEX IF NOT EXISTS idx_user_attributes_username ON user_attributes(username, attribute_type);

-- Insert test users with different password hashing algorithms
-- Note: These are pre-computed hashes for testing

-- Test user with bcrypt password (password: password123)
INSERT INTO users (username, password_hash, enabled) VALUES
('testuser_bcrypt', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ztpql7VJ7hO6', true)
ON CONFLICT (username) DO NOTHING;

-- Test user with Argon2 password (password: password123)
-- Generated with: argon2 "password123" -id -e
INSERT INTO users (username, password_hash, enabled) VALUES
('testuser_argon2', '$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0$GpZ3sK/oH9p7U9/fq1QkwCj1hGCYw3N9u1EcI5z89KE', true)
ON CONFLICT (username) DO NOTHING;

-- Test user with PBKDF2 password (password: password123)
-- Generated with Python: from passlib.hash import pbkdf2_sha256; pbkdf2_sha256.hash("password123")
INSERT INTO users (username, password_hash, enabled) VALUES
('testuser_pbkdf2', '$pbkdf2-sha256$29000$N2bMuRciZCwlhPD.v9c6Zw$1t8iyB2A.WF/Z5JZv.WCfTjyb3UUTfGbQO8D.6fBKHw', true)
ON CONFLICT (username) DO NOTHING;

-- Admin user with bcrypt (password: admin123)
INSERT INTO users (username, password_hash, enabled) VALUES
('adminuser', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', true)
ON CONFLICT (username) DO NOTHING;

-- Disabled user for testing access control
INSERT INTO users (username, password_hash, enabled) VALUES
('disableduser', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ztpql7VJ7hO6', false)
ON CONFLICT (username) DO NOTHING;

-- Insert test user attributes
INSERT INTO user_attributes (username, attribute_type, attribute_value) VALUES
('testuser_bcrypt', 'Service-Type', 'Framed-User'),
('testuser_bcrypt', 'Framed-Protocol', 'PPP'),
('testuser_bcrypt', 'Framed-IP-Address', '192.168.1.100'),
('testuser_bcrypt', 'Framed-Netmask', '255.255.255.0'),
('adminuser', 'Service-Type', 'Administrative-User'),
('adminuser', 'Session-Timeout', '7200'),
('testuser_argon2', 'Service-Type', 'Framed-User'),
('testuser_pbkdf2', 'Service-Type', 'Framed-User')
ON CONFLICT DO NOTHING;

-- Verify data was inserted
SELECT 'Test users created:' AS status;
SELECT username, enabled, created_at FROM users ORDER BY username;

SELECT 'User attributes created:' AS status;
SELECT username, attribute_type, attribute_value FROM user_attributes ORDER BY username, attribute_type;
