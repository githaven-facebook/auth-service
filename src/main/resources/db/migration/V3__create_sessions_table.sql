CREATE TABLE sessions (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token            VARCHAR(512) NOT NULL,
    ip_address       VARCHAR(45),
    user_agent       VARCHAR(512),
    expires_at       TIMESTAMPTZ  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ,
    revoked          BOOLEAN      NOT NULL DEFAULT FALSE,

    CONSTRAINT uq_sessions_token UNIQUE (token)
);

CREATE INDEX idx_sessions_token           ON sessions (token)           WHERE revoked = FALSE;
CREATE INDEX idx_sessions_user_id         ON sessions (user_id);
CREATE INDEX idx_sessions_user_active     ON sessions (user_id, revoked, expires_at);
CREATE INDEX idx_sessions_expires_revoked ON sessions (expires_at)      WHERE revoked = TRUE;

COMMENT ON TABLE  sessions           IS 'Active and historical user sessions';
COMMENT ON COLUMN sessions.token     IS 'Stores refresh token value for session binding';
COMMENT ON COLUMN sessions.revoked   IS 'Soft-delete flag; revoked sessions are kept for audit';
