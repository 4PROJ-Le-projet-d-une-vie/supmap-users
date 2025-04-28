-- +goose Up
-- +goose StatementBegin
CREATE TABLE routes
(
    id         SERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name       TEXT,
    route      JSONB  NOT NULL,
    created_at TIMESTAMPTZ(0) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ(0) DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE routes;
-- +goose StatementEnd
