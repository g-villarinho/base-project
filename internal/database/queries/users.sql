-- name: CreateUser :exec
INSERT INTO users (id, name, email, status, password_hash, created_at, updated_at, email_confirmed_at, blocked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: FindUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: FindUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: ExistsByEmail :one
SELECT COUNT(*) > 0 FROM users WHERE email = ?;

-- name: UpdateUserEmail :execresult
UPDATE users
SET email = ?, updated_at = ?
WHERE id = ?;

-- name: UpdateUserPassword :execresult
UPDATE users
SET password_hash = ?, updated_at = ?
WHERE id = ?;

-- name: VerifyUserEmail :execresult
UPDATE users
SET status = 'ACTIVE',
    updated_at = ?,
    email_confirmed_at = ?
WHERE id = ?;

-- name: BlockUser :execresult
UPDATE users
SET status = 'BLOCKED',
    updated_at = ?,
    blocked_at = ?
WHERE id = ?;

-- name: UpdateUserName :execresult
UPDATE users
SET name = ?, updated_at = ?
WHERE id = ?;
