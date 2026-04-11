CREATE TABLE roles (
    id          BIGSERIAL    PRIMARY KEY,
    name        VARCHAR(50)  NOT NULL,
    description VARCHAR(255),

    CONSTRAINT uq_roles_name UNIQUE (name)
);

CREATE TABLE permissions (
    id          BIGSERIAL    PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    resource    VARCHAR(100) NOT NULL,
    action      VARCHAR(50)  NOT NULL,
    description VARCHAR(255),

    CONSTRAINT uq_permissions_name UNIQUE (name)
);

CREATE TABLE role_permissions (
    role_id       BIGINT NOT NULL REFERENCES roles(id)       ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_role_permissions_role_id   ON role_permissions (role_id);
CREATE INDEX idx_role_permissions_perm_id   ON role_permissions (permission_id);
CREATE INDEX idx_user_roles_user_id         ON user_roles (user_id);
CREATE INDEX idx_user_roles_role_id         ON user_roles (role_id);

COMMENT ON TABLE roles       IS 'RBAC roles assignable to users';
COMMENT ON TABLE permissions IS 'Fine-grained permissions associated with roles';
