package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/JRI98/yeomessaging/client/database/queries"
	"github.com/JRI98/yeomessaging/internal/ed25519"
	"github.com/JRI98/yeomessaging/internal/x25519"
	"github.com/JRI98/yeomessaging/internal/xchacha20poly1305"
)

func (database *Database) CreatePassword(ctx context.Context, salt []byte) error {
	return database.queries.CreatePassword(ctx, salt)
}

func (database *Database) GetPassword(ctx context.Context) ([]byte, error) {
	return database.queries.GetPassword(ctx)
}

type CreateChatParams struct {
	PrivateIdentityKey ed25519.PrivateKey
	Title              string
	Description        string
}

func (database *Database) CreateChat(ctx context.Context, params CreateChatParams) (int64, error) {
	privateIdentityKey, err := xchacha20poly1305.Encrypt(params.PrivateIdentityKey, database.encryptionKey)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt private identity key: %w", err)
	}

	title, err := xchacha20poly1305.Encrypt([]byte(params.Title), database.encryptionKey)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt title: %w", err)
	}

	description, err := xchacha20poly1305.Encrypt([]byte(params.Description), database.encryptionKey)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt description: %w", err)
	}

	arg := queries.CreateChatParams{
		EncryptedPrivateIdentityKey: privateIdentityKey,
		EncryptedTitle:              title,
		EncryptedDescription:        description,
	}

	chatId, err := database.queries.CreateChat(ctx, arg)
	if err != nil {
		return 0, fmt.Errorf("failed to create chat: %w", err)
	}

	return chatId, nil
}

type GetChatsChat struct {
	ChatID      int64
	Title       string
	Description string
}

func (database *Database) GetChats(ctx context.Context) ([]GetChatsChat, error) {
	chats, err := database.queries.GetChats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chats: %w", err)
	}

	resultChats := make([]GetChatsChat, 0, len(chats))
	for _, chat := range chats {
		title, err := xchacha20poly1305.Decrypt(chat.EncryptedTitle, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt title: %w", err)
		}

		description, err := xchacha20poly1305.Decrypt(chat.EncryptedDescription, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt description: %w", err)
		}

		resultChats = append(resultChats, GetChatsChat{
			ChatID:      chat.ChatID,
			Title:       string(title),
			Description: string(description),
		})
	}

	return resultChats, nil
}

type GetChatChat struct {
	ChatID             int64
	Title              string
	Description        string
	PrivateIdentityKey ed25519.PrivateKey
}

func (database *Database) GetChat(ctx context.Context, chatID int64) (GetChatChat, error) {
	chat, err := database.queries.GetChat(ctx, chatID)
	if err != nil {
		return GetChatChat{}, fmt.Errorf("failed to get chat: %w", err)
	}

	title, err := xchacha20poly1305.Decrypt(chat.EncryptedTitle, database.encryptionKey)
	if err != nil {
		return GetChatChat{}, fmt.Errorf("failed to decrypt title: %w", err)
	}

	description, err := xchacha20poly1305.Decrypt(chat.EncryptedDescription, database.encryptionKey)
	if err != nil {
		return GetChatChat{}, fmt.Errorf("failed to decrypt description: %w", err)
	}

	privateIdentityKey, err := xchacha20poly1305.Decrypt(chat.EncryptedPrivateIdentityKey, database.encryptionKey)
	if err != nil {
		return GetChatChat{}, fmt.Errorf("failed to decrypt private identity key: %w", err)
	}

	return GetChatChat{
		ChatID:             chatID,
		Title:              string(title),
		Description:        string(description),
		PrivateIdentityKey: privateIdentityKey,
	}, nil
}

type UpdateChatParams struct {
	ChatID      int64
	Title       string
	Description string
}

func (database *Database) UpdateChat(ctx context.Context, params UpdateChatParams) error {
	title, err := xchacha20poly1305.Encrypt([]byte(params.Title), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt title: %w", err)
	}

	description, err := xchacha20poly1305.Encrypt([]byte(params.Description), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt description: %w", err)
	}

	return database.queries.UpdateChat(ctx, queries.UpdateChatParams{
		EncryptedTitle:       title,
		EncryptedDescription: description,
		ChatID:               params.ChatID,
	})
}

type CreateParticipantParams struct {
	ChatID            int64
	SequenceNumber    int64
	PublicIdentityKey ed25519.PublicKey
	Name              string
	EcdhPublicKey     *x25519.PublicKey
	MyEcdhPrivateKey  *x25519.PrivateKey
}

func (database *Database) CreateParticipant(ctx context.Context, params CreateParticipantParams) error {
	publicIdentityKey, err := xchacha20poly1305.Encrypt(params.PublicIdentityKey, database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt public identity key: %w", err)
	}

	name, err := xchacha20poly1305.Encrypt([]byte(params.Name), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt name: %w", err)
	}

	ecdhPublicKey, err := xchacha20poly1305.Encrypt(params.EcdhPublicKey.Bytes(), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt ecdh public key: %w", err)
	}

	myEcdhPrivateKey, err := xchacha20poly1305.Encrypt(params.MyEcdhPrivateKey.Bytes(), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt my ecdh private key: %w", err)
	}

	return database.queries.CreateParticipant(ctx, queries.CreateParticipantParams{
		ChatID:                     params.ChatID,
		SequenceNumber:             params.SequenceNumber,
		EncryptedPublicIdentityKey: publicIdentityKey,
		EncryptedName:              name,
		EncryptedEcdhPublicKey:     ecdhPublicKey,
		EncryptedMyEcdhPrivateKey:  myEcdhPrivateKey,
	})
}

type Participant struct {
	SequenceNumber    int64
	PublicIdentityKey ed25519.PublicKey
	Name              string
	EcdhPublicKey     *x25519.PublicKey
	MyEcdhPrivateKey  *x25519.PrivateKey
}

func (database *Database) GetParticipants(ctx context.Context, chatID int64) (map[string]*Participant, error) {
	participants, err := database.queries.GetParticipants(ctx, chatID)
	if err != nil {
		return nil, fmt.Errorf("failed to get chat participants: %w", err)
	}

	resultParticipants := make(map[string]*Participant, len(participants))
	for _, participant := range participants {
		publicIdentityKey, err := xchacha20poly1305.Decrypt(participant.EncryptedPublicIdentityKey, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt public identity key: %w", err)
		}

		name, err := xchacha20poly1305.Decrypt(participant.EncryptedName, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt name: %w", err)
		}

		ecdhPublicKeyBytes, err := xchacha20poly1305.Decrypt(participant.EncryptedEcdhPublicKey, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt ecdh public key: %w", err)
		}

		ecdhPublicKey, err := x25519.PublicKeyFromBytes(ecdhPublicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ecdh public key: %w", err)
		}

		myEcdhPrivateKeyBytes, err := xchacha20poly1305.Decrypt(participant.EncryptedMyEcdhPrivateKey, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt my ecdh private key: %w", err)
		}

		myEcdhPrivateKey, err := x25519.PrivateKeyFromBytes(myEcdhPrivateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse my ecdh private key: %w", err)
		}

		resultParticipants[string(publicIdentityKey)] = &Participant{
			SequenceNumber:    participant.SequenceNumber,
			PublicIdentityKey: publicIdentityKey,
			Name:              string(name),
			EcdhPublicKey:     ecdhPublicKey,
			MyEcdhPrivateKey:  myEcdhPrivateKey,
		}
	}

	return resultParticipants, nil
}

type UpdateParticipantParams struct {
	ChatID           int64
	SequenceNumber   int64
	Name             string
	EcdhPublicKey    *x25519.PublicKey
	MyEcdhPrivateKey *x25519.PrivateKey
}

func (database *Database) UpdateParticipant(ctx context.Context, params UpdateParticipantParams) error {
	name, err := xchacha20poly1305.Encrypt([]byte(params.Name), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt name: %w", err)
	}

	ecdhPublicKey, err := xchacha20poly1305.Encrypt(params.EcdhPublicKey.Bytes(), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt ecdh public key: %w", err)
	}

	myEcdhPrivateKey, err := xchacha20poly1305.Encrypt(params.MyEcdhPrivateKey.Bytes(), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt my ecdh private key: %w", err)
	}

	return database.queries.UpdateParticipant(ctx, queries.UpdateParticipantParams{
		EncryptedName:             name,
		EncryptedEcdhPublicKey:    ecdhPublicKey,
		EncryptedMyEcdhPrivateKey: myEcdhPrivateKey,
		ChatID:                    params.ChatID,
		SequenceNumber:            params.SequenceNumber,
	})
}

type CreateMessageParams struct {
	ChatID            int64
	SequenceNumber    int64
	PublicIdentityKey ed25519.PublicKey
	Content           string
	CreatedAt         time.Time
}

func (database *Database) CreateMessage(ctx context.Context, params CreateMessageParams) error {
	publicIdentityKey, err := xchacha20poly1305.Encrypt(params.PublicIdentityKey, database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt public identity key: %w", err)
	}

	content, err := xchacha20poly1305.Encrypt([]byte(params.Content), database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt content: %w", err)
	}

	createdAt, err := params.CreatedAt.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal created at: %w", err)
	}

	createdAt, err = xchacha20poly1305.Encrypt(createdAt, database.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt created at: %w", err)
	}

	return database.queries.CreateMessage(ctx, queries.CreateMessageParams{
		ChatID:                     params.ChatID,
		SequenceNumber:             params.SequenceNumber,
		EncryptedPublicIdentityKey: publicIdentityKey,
		EncryptedContent:           content,
		EncryptedCreatedAt:         createdAt,
	})
}

type Message struct {
	SequenceNumber    int64
	PublicIdentityKey ed25519.PublicKey
	Content           string
	CreatedAt         time.Time
}

func (database *Database) GetMessages(ctx context.Context, chatID int64) ([]Message, error) {
	messages, err := database.queries.GetMessages(ctx, chatID)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages: %w", err)
	}

	resultMessages := make([]Message, 0, len(messages))
	for _, message := range messages {
		publicIdentityKey, err := xchacha20poly1305.Decrypt(message.EncryptedPublicIdentityKey, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt public identity key: %w", err)
		}

		content, err := xchacha20poly1305.Decrypt(message.EncryptedContent, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt content: %w", err)
		}

		createdAtBytes, err := xchacha20poly1305.Decrypt(message.EncryptedCreatedAt, database.encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt created at: %w", err)
		}

		var createdAt time.Time
		err = createdAt.UnmarshalBinary(createdAtBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal created at: %w", err)
		}

		resultMessages = append(resultMessages, Message{
			SequenceNumber:    message.SequenceNumber,
			PublicIdentityKey: publicIdentityKey,
			Content:           string(content),
			CreatedAt:         createdAt,
		})
	}

	return resultMessages, nil
}

func (database *Database) GetNextSequenceNumber(ctx context.Context, chatID int64) (int64, error) {
	nextSequenceNumber, err := database.queries.GetNextSequenceNumber(ctx, chatID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}

		return 0, fmt.Errorf("failed to get next sequence number: %w", err)
	}

	return nextSequenceNumber + 1, nil
}
