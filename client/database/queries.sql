-- name: CreatePassword :exec
INSERT INTO password (
  id, salt
) VALUES (0, ?);

-- name: GetPassword :one
SELECT salt FROM password;

-- name: CreateChat :one
INSERT INTO chats (
  encrypted_private_identity_key, encrypted_title, encrypted_description
) VALUES (?, ?, ?)
RETURNING chat_id;

-- name: GetChats :many
SELECT chat_id, encrypted_title, encrypted_description FROM chats
ORDER BY chat_id ASC;

-- name: GetChat :one
SELECT * FROM chats
WHERE chat_id = ?;

-- name: UpdateChat :exec
UPDATE chats
SET encrypted_title = ?,
    encrypted_description = ?
WHERE chat_id = ?;

-- name: CreateParticipant :exec
INSERT INTO participants (
  chat_id, sequence_number, encrypted_public_identity_key, encrypted_name, encrypted_ecdh_public_key, encrypted_my_ecdh_private_key
) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetParticipants :many
SELECT * FROM participants
WHERE chat_id = ?;

-- name: UpdateParticipant :exec
UPDATE participants
SET encrypted_name = ?,
    encrypted_ecdh_public_key = ?,
    encrypted_my_ecdh_private_key = ?
WHERE chat_id = ? AND sequence_number = ?;

-- name: CreateMessage :exec
INSERT INTO messages (
  chat_id, sequence_number, encrypted_public_identity_key, encrypted_content, encrypted_created_at
) VALUES (?, ?, ?, ?, ?);

-- name: GetMessages :many
SELECT * FROM messages
WHERE chat_id = ?
ORDER BY sequence_number ASC;

-- name: GetNextSequenceNumber :one
SELECT sequence_number FROM messages
WHERE chat_id = ?
ORDER BY sequence_number DESC
LIMIT 1;
