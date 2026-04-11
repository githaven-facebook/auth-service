CREATE TABLE two_factor_secrets (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret      VARCHAR(64) NOT NULL,
    enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_2fa_user_id UNIQUE (user_id)
);

CREATE TABLE two_factor_backup_codes (
    two_factor_secret_id UUID         NOT NULL REFERENCES two_factor_secrets(id) ON DELETE CASCADE,
    backup_code_hash     VARCHAR(255) NOT NULL
);

CREATE INDEX idx_2fa_user_id         ON two_factor_secrets (user_id);
CREATE INDEX idx_2fa_backup_secret   ON two_factor_backup_codes (two_factor_secret_id);

COMMENT ON TABLE  two_factor_secrets              IS 'TOTP secrets and backup codes for 2FA';
COMMENT ON COLUMN two_factor_secrets.secret       IS 'Base32-encoded TOTP secret';
COMMENT ON COLUMN two_factor_backup_codes.backup_code_hash IS 'BCrypt-hashed single-use backup code';
