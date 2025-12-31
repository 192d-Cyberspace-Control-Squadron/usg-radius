-- Test data for PostgreSQL integration tests
-- This file is loaded after the schema is created

-- Insert test users with bcrypt password hashes
-- Passwords:
--   testuser: password123
--   alice: alice123
--   bob: bob456
--   disabled: disabled123 (but account is disabled)

INSERT INTO users (username, password_hash, enabled) VALUES
    ('testuser', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqJxm1O3yG', true),
    ('alice', '$2b$12$KSdL5K91f8.1H0jvR6F5wOf8jCPP3E2VQh4RKmjX7vP5ZJQjD2jNu', true),
    ('bob', '$2b$12$yGqMZq.1TqLqE1F5wOL8vOH0jvR6F5wOf8jCPP3E2VQh4RKmjX7vP', true),
    ('disabled', '$2b$12$aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH7iJ', false)
ON CONFLICT (username) DO NOTHING;

-- Add RADIUS attributes for test users
INSERT INTO user_attributes (username, attribute_type, attribute_value) VALUES
    -- testuser attributes
    ('testuser', 6, '2'),          -- Service-Type: Framed
    ('testuser', 27, '3600'),      -- Session-Timeout: 1 hour

    -- alice attributes (admin user with more permissions)
    ('alice', 6, '2'),             -- Service-Type: Framed
    ('alice', 27, '7200'),         -- Session-Timeout: 2 hours
    ('alice', 11, 'admin-filter'), -- Filter-Id: admin-filter

    -- bob attributes (basic user)
    ('bob', 6, '2'),               -- Service-Type: Framed
    ('bob', 27, '1800')            -- Session-Timeout: 30 minutes
ON CONFLICT (username, attribute_type, attribute_value) DO NOTHING;

-- Insert some test authentication attempts for audit trail testing
INSERT INTO auth_attempts (username, source_ip, success, nas_identifier, nas_ip_address) VALUES
    ('testuser', '127.0.0.1', true, 'test-nas', '192.168.1.1'),
    ('alice', '127.0.0.1', true, 'test-nas', '192.168.1.1'),
    ('bob', '127.0.0.1', false, 'test-nas', '192.168.1.1'),
    ('unknown', '127.0.0.1', false, 'test-nas', '192.168.1.1');
