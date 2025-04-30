-- +goose Up
-- +goose StatementBegin
ALTER TABLE refresh_tokens DROP COLUMN ip;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE refresh_tokens ADD COLUMN ip inet;
-- +goose StatementEnd
