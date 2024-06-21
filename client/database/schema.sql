CREATE TABLE IF NOT EXISTS chats (
  chat_id INTEGER NOT NULL,
  encrypted_private_identity_key BLOB NOT NULL,
  encrypted_title BLOB NOT NULL,
  encrypted_description BLOB NOT NULL,

  PRIMARY KEY (chat_id)
);

CREATE TABLE IF NOT EXISTS participants (
  chat_id INTEGER NOT NULL REFERENCES chats(chat_id),
  sequence_number INTEGER NOT NULL,
  encrypted_public_identity_key BLOB NOT NULL,
  encrypted_name BLOB NOT NULL,
  encrypted_ecdh_public_key BLOB NOT NULL,
  encrypted_my_ecdh_private_key BLOB NOT NULL,

  PRIMARY KEY (chat_id, encrypted_public_identity_key)
);

CREATE TABLE IF NOT EXISTS messages (
  chat_id INTEGER NOT NULL REFERENCES chats(chat_id),
  sequence_number INTEGER NOT NULL,
  encrypted_public_identity_key BLOB NOT NULL,
  encrypted_content BLOB NOT NULL,
  encrypted_created_at BLOB NOT NULL,

  PRIMARY KEY (chat_id, sequence_number)
);

CREATE TABLE IF NOT EXISTS password (
  id INTEGER NOT NULL CHECK (id = 0),
  salt BLOB NOT NULL,

  PRIMARY KEY (id)
);
