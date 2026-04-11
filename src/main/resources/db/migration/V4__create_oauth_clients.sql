CREATE TABLE oauth_clients (
    client_id                  VARCHAR(100) PRIMARY KEY,
    client_secret              VARCHAR(255) NOT NULL,
    client_name                VARCHAR(100) NOT NULL,
    access_token_ttl_seconds   INTEGER      NOT NULL DEFAULT 900,
    refresh_token_ttl_seconds  INTEGER      NOT NULL DEFAULT 604800,
    active                     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE oauth_client_redirect_uris (
    client_id    VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri VARCHAR(255) NOT NULL,

    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE oauth_client_grant_types (
    client_id  VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    grant_type VARCHAR(50)  NOT NULL,

    PRIMARY KEY (client_id, grant_type)
);

CREATE TABLE oauth_client_scopes (
    client_id VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scope     VARCHAR(50)  NOT NULL,

    PRIMARY KEY (client_id, scope)
);

COMMENT ON TABLE oauth_clients IS 'Registered OAuth2 client applications';
