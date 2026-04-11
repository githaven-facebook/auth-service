CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                       VARCHAR(255) NOT NULL,
    username                    VARCHAR(50)  NOT NULL,
    password_hash               VARCHAR(255) NOT NULL,
    display_name                VARCHAR(100),
    email_verified              BOOLEAN      NOT NULL DEFAULT FALSE,
    account_locked              BOOLEAN      NOT NULL DEFAULT FALSE,
    failed_login_attempts       INTEGER      NOT NULL DEFAULT 0,
    last_login_at               TIMESTAMPTZ,
    email_verification_token    VARCHAR(255),
    password_reset_token        VARCHAR(255),
    password_reset_expires_at   TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_users_email    UNIQUE (email),
    CONSTRAINT uq_users_username UNIQUE (username)
);

CREATE INDEX idx_users_email                    ON users (email);
CREATE INDEX idx_users_username                 ON users (username);
CREATE INDEX idx_users_email_verification_token ON users (email_verification_token) WHERE email_verification_token IS NOT NULL;
CREATE INDEX idx_users_password_reset_token     ON users (password_reset_token)     WHERE password_reset_token IS NOT NULL;

COMMENT ON TABLE  users                      IS 'Core user accounts for authentication';
COMMENT ON COLUMN users.password_hash        IS 'BCrypt-hashed password (strength 12)';
COMMENT ON COLUMN users.failed_login_attempts IS 'Consecutive failed login counter; reset on success';
