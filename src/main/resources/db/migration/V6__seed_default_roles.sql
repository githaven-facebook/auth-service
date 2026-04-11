-- Insert default roles
INSERT INTO roles (name, description) VALUES
    ('USER',      'Default role for all registered users'),
    ('ADMIN',     'Full administrative access'),
    ('MODERATOR', 'Content and user moderation access'),
    ('SERVICE',   'Internal service-to-service access');

-- Insert permissions
INSERT INTO permissions (name, resource, action, description) VALUES
    -- User permissions
    ('user:read:own',    'user', 'read',   'Read own user profile'),
    ('user:write:own',   'user', 'write',  'Update own user profile'),
    ('user:read:any',    'user', 'read',   'Read any user profile'),
    ('user:write:any',   'user', 'write',  'Update any user profile'),
    ('user:delete:any',  'user', 'delete', 'Delete any user account'),
    ('user:lock:any',    'user', 'lock',   'Lock/unlock any user account'),

    -- Session permissions
    ('session:read:own',   'session', 'read',   'Read own sessions'),
    ('session:delete:own', 'session', 'delete', 'Delete own sessions'),
    ('session:read:any',   'session', 'read',   'Read any user sessions'),
    ('session:delete:any', 'session', 'delete', 'Delete any user sessions'),

    -- Role/Permission management
    ('role:assign', 'role', 'assign', 'Assign roles to users'),
    ('role:revoke', 'role', 'revoke', 'Revoke roles from users'),
    ('role:read',   'role', 'read',   'Read roles and permissions'),

    -- API permissions
    ('api:read',  'api', 'read',  'Read access to API resources'),
    ('api:write', 'api', 'write', 'Write access to API resources');

-- Assign permissions to roles
-- USER role permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'USER'
  AND p.name IN ('user:read:own', 'user:write:own', 'session:read:own', 'session:delete:own', 'api:read');

-- ADMIN role permissions (all permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ADMIN';

-- MODERATOR role permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'MODERATOR'
  AND p.name IN ('user:read:any', 'user:lock:any', 'session:read:any', 'session:delete:any', 'api:read');

-- SERVICE role permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'SERVICE'
  AND p.name IN ('user:read:any', 'api:read', 'api:write');
