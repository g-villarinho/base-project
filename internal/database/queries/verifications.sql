-- name: CreateVerification :exec
INSERT INTO verifications (id, flow, token, created_at, expires_at, payload, user_id)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: FindVerificationByID :one
SELECT * FROM verifications WHERE id = ?;

-- name: FindVerificationByToken :one
SELECT * FROM verifications WHERE token = ?;

-- name: DeleteVerification :execresult
DELETE FROM verifications WHERE id = ?;

-- name: FindValidVerificationByUserIDAndFlow :one
SELECT * FROM verifications
WHERE user_id = ?
  AND flow = ?
  AND expires_at > ?
ORDER BY created_at DESC
LIMIT 1;

-- name: DeleteVerificationsByUserIDAndFlow :exec
DELETE FROM verifications
WHERE user_id = ?
  AND flow = ?
  AND expires_at > ?;
