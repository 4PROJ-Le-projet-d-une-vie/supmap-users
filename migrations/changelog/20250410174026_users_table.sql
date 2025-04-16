-- +goose Up
-- +goose StatementBegin
CREATE TABLE roles
(
    id   SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE users
(
    id              SERIAL PRIMARY KEY,

    email           TEXT UNIQUE NOT NULL,
    handle          TEXT UNIQUE NOT NULL CHECK (handle LIKE '@%'),

    password_hash   TEXT, -- NULL si provider externe
    auth_provider   TEXT        NOT NULL DEFAULT 'local' CHECK (auth_provider IN ('local', 'google', 'github', 'facebook')),

    profile_picture TEXT,
    role_id         INT         NOT NULL REFERENCES roles (id),

    created_at      TIMESTAMPTZ(0)          DEFAULT NOW(),
    updated_at      TIMESTAMPTZ(0)          DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
DROP TABLE roles;
-- +goose StatementEnd
