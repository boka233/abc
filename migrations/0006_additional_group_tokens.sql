-- Newly issued install commands must not revoke credentials used by running agents.
-- Tokens have 40 random characters, so an indexed SHA-256 digest is safe and
-- avoids an Argon2 check for every issued command on every heartbeat.
CREATE TABLE device_group_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    group_id TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    token_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_device_group_tokens_group_id ON device_group_tokens (group_id);
