-- Test data for PostgreSQL integration tests
-- This file is loaded after the schema is created

-- Insert test users with bcrypt password hashes
-- Passwords:
--   testuser: password123
--   alice: alice123
--   bob: bob456
--   disabled: disabled123 (but account is disabled)

INSERT INTO users (username, password_hash, enabled) VALUES
    ('testuser', '$2b$12$vMsD81dcf/ga2G8eAux9hO1QzSu8bZbAZBGMnttsWEJ05QQzryqeC', true),
    ('alice', '$2b$12$LVDpbqZhE5PWYTd1hZb4A.b1EJoJ1QAWs8XIwdPBDz0StqRcLyQGy', true),
    ('bob', '$2b$12$1u1CL.AzbwgOWNE0pqV0MeGs4PQWBSISoewyPx3TzikQS35mOa2hW', true),
    ('disabled', '$2b$12$uIjpdHMWobqRd5ku3SC4LOFbJHFUCojCce0E6.920OupgX6bBv1IO', false)
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
