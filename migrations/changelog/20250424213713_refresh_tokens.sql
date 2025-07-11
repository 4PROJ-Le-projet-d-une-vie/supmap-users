-- +goose Up
-- +goose StatementBegin
CREATE TABLE refresh_tokens (
    user_id SERIAL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ip inet NOT NULL,
    token text NOT NULL,
    created_at TIMESTAMPTZ(0) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz(0) NOT NULL
);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_refresh_tokens_expires_at;
DROP TABLE refresh_tokens;
-- +goose StatementEnd
