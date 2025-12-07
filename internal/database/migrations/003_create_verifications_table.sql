-- +migrate Up
CREATE TABLE IF NOT EXISTS verifications (
    id VARCHAR(36) PRIMARY KEY,
    flow VARCHAR(20) NOT NULL CHECK (flow IN ('RESET_PASSWORD', 'VERIFICATION_EMAIL', 'CHANGE_EMAIL')),
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    payload TEXT,
    user_id VARCHAR(36) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_verifications_token ON verifications(token);
CREATE INDEX idx_verifications_expires_at ON verifications(expires_at);

-- +migrate Down
DROP INDEX IF EXISTS idx_verifications_expires_at;
DROP INDEX IF EXISTS idx_verifications_token;
DROP TABLE IF EXISTS verifications;
