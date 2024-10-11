package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/JRI98/incognitomessaging/client/database"
	"github.com/JRI98/incognitomessaging/internal/argon2id"
	"github.com/JRI98/incognitomessaging/internal/cryptorandom"
	"github.com/JRI98/incognitomessaging/internal/ed25519"
	"github.com/JRI98/incognitomessaging/internal/x25519"
	"github.com/JRI98/incognitomessaging/internal/xchacha20poly1305"
	"golang.org/x/term"
)

const serverURL = "http://localhost:3000"

func readPassword() ([]byte, error) {
	fmt.Print("Password: ")
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return password, nil
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

type Args struct {
	DatabasePath string
}

func getArgs() Args {
	databasePath := flag.String("db", "database.db", "Path to the database file")

	flag.Parse()

	return Args{
		DatabasePath: *databasePath,
	}
}

func setHeaders(req *http.Request, privateIdentityKey ed25519.PrivateKey, body []byte) {
	publicIdentityKey := privateIdentityKey.Public().(ed25519.PublicKey)
	bodySignature := ed25519.Sign(privateIdentityKey, body)

	payload := make([]byte, 0, len(publicIdentityKey)+len(bodySignature))
	payload = append(payload, publicIdentityKey...)
	payload = append(payload, bodySignature...)

	req.Header.Set("Authorization", base64.StdEncoding.EncodeToString(payload))
}

type RegisterData struct {
	PublicIdentityKeys [][]byte `json:"public_identity_keys"`
}

func register(privateIdentityKey ed25519.PrivateKey, data RegisterData) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	bodyReader := bytes.NewReader(dataBytes)

	requestURL := fmt.Sprintf("%s/api/register", serverURL)
	request, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")

	setHeaders(request, privateIdentityKey, dataBytes)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	return nil
}

type ReceiveMessage struct {
	FromPublicIdentityKey []byte `json:"from_public_identity_key"`
	Data                  []byte `json:"data"`
	CreatedAt             int64  `json:"created_at"`
}

func receiveMessages(privateIdentityKey ed25519.PrivateKey) ([]ReceiveMessage, error) {
	requestURL := fmt.Sprintf("%s/api/messages", serverURL)
	request, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	setHeaders(request, privateIdentityKey, nil)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var messages []ReceiveMessage
	err = json.Unmarshal(responseBody, &messages)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	return messages, nil
}

type SendMessage struct {
	ToPublicIdentityKey []byte `json:"to_public_identity_key"`
	Data                []byte `json:"data"`
}

type SendMessagesData struct {
	Messages []SendMessage `json:"messages"`
	Index    uint64        `json:"index"`
}

func sendMessages(privateIdentityKey ed25519.PrivateKey, data SendMessagesData) (_retry bool, _error error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return false, fmt.Errorf("failed to marshal data: %w", err)
	}

	bodyReader := bytes.NewReader(dataBytes)

	requestURL := fmt.Sprintf("%s/api/messages", serverURL)
	request, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")

	setHeaders(request, privateIdentityKey, dataBytes)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusConflict {
		return true, fmt.Errorf("outdated message index")
	}

	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	return false, nil
}

type Program struct {
	database *database.Database
	stdin    *bufio.Reader
	context  context.Context
}

func (program Program) readInput() (string, error) {
	text, err := program.stdin.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return text[:len(text)-1], nil
}

func main() {
	clearScreen()

	args := getArgs()

	ctx := context.Background()

	database, err := database.Open(args.DatabasePath)
	if err != nil {
		panic(fmt.Errorf("failed to open database: %w", err))
	}
	defer database.Close()

	passwordSalt, err := database.GetPassword(ctx)

	var password []byte
	if errors.Is(err, sql.ErrNoRows) {
		password, err = readPassword()
		if err != nil {
			panic(fmt.Errorf("failed to read password: %w", err))
		}

		passwordSalt, err = cryptorandom.RandomBytes(argon2id.SaltLen)
		if err != nil {
			panic(fmt.Errorf("failed to generate salt: %w", err))
		}

		err = database.CreatePassword(ctx, passwordSalt)
		if err != nil {
			panic(fmt.Errorf("failed to create password: %w", err))
		}

	} else {
		password, err = readPassword()
		if err != nil {
			panic(fmt.Errorf("failed to read password: %w", err))
		}

	}

	databaseEncryptionKey, err := argon2id.HashKDF32(password, passwordSalt)
	if err != nil {
		panic(fmt.Errorf("failed to hash password: %w", err))
	}

	err = database.SetEncryptionKey(databaseEncryptionKey)
	if err != nil {
		panic(fmt.Errorf("failed to set encryption key: %w", err))
	}

	stdin := bufio.NewReader(os.Stdin)

	program := Program{
		database: database,
		stdin:    stdin,
		context:  ctx,
	}

	err = program.mainScreen()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		panic(fmt.Errorf("main screen error: %w", err))
	}
}

func (program Program) mainScreen() error {
	for {
		clearScreen()

		fmt.Println("1. Get Chats")
		fmt.Println("2. Create Chat")
		fmt.Println("3. Quit")
		fmt.Print("> ")
		action, err := program.readInput()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		switch action {
		case "1":
			err := program.chatsScreen()
			if err != nil {
				return fmt.Errorf("chats screen error: %w", err)
			}
		case "2":
			err := program.createChatScreen()
			if err != nil {
				return fmt.Errorf("create chat screen error: %w", err)
			}
		case "3":
			clearScreen()
			return nil
		}
	}
}

func (program Program) chatsScreen() error {
	for {
		clearScreen()

		chats, err := program.database.GetChats(program.context)
		if err != nil {
			return fmt.Errorf("failed to get chats: %w", err)
		}

		if len(chats) == 0 {
			fmt.Println("No chats")
			fmt.Print("Press enter to return...")
			_, err := program.readInput()
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}
			return nil
		}

		for i, chat := range chats {
			fmt.Printf("%d. %s\n", i+1, chat.Title)
		}

		fmt.Printf("Enter chat number (or %d to go back): ", len(chats)+1)
		chatNumber, err := program.readInput()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		action, err := strconv.ParseUint(chatNumber, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse chat number: %w", err)
		}

		if action == uint64(len(chats)+1) {
			return nil
		}

		err = program.chatScreen(chats[action-1].ChatID)
		if err != nil {
			return fmt.Errorf("chat screen error: %w", err)
		}
	}
}

func (program Program) chatScreen(chatId int64) error {
	for {
		clearScreen()

		chat, err := program.database.GetChat(program.context, chatId)
		if err != nil {
			return fmt.Errorf("failed to get chat: %w", err)
		}

		fmt.Printf("%s: %s\n", chat.Title, chat.Description)
		fmt.Println("1. Update")
		fmt.Println("2. Get Participants")
		fmt.Println("3. View Messages")
		fmt.Println("4. Send Message")
		fmt.Println("5. Go Back")
		fmt.Print("> ")
		action, err := program.readInput()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		switch action {
		case "1":
			err := program.updateChatScreen(chat)
			if err != nil {
				return fmt.Errorf("update chat screen error: %w", err)
			}
		case "2":
			err := program.participantsScreen(chat)
			if err != nil {
				return fmt.Errorf("participants screen error: %w", err)
			}
		case "3":
			err := program.messagesScreen(chat)
			if err != nil {
				return fmt.Errorf("messages screen error: %w", err)
			}
		case "4":
			err := program.sendMessageScreen(chat)
			if err != nil {
				return fmt.Errorf("send message screen error: %w", err)
			}
		case "5":
			clearScreen()
			return nil
		}
	}
}

func (program Program) updateChatScreen(chat database.GetChatChat) error {
	fmt.Print("Title: ")
	title, err := program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if title == "" {
		title = chat.Title
	}

	fmt.Print("Description: ")
	description, err := program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if description == "" {
		description = chat.Description
	}

	err = program.database.UpdateChat(program.context, database.UpdateChatParams{
		ChatID:      chat.ChatID,
		Title:       title,
		Description: description,
	})
	if err != nil {
		return fmt.Errorf("failed to update chat: %w", err)
	}

	return nil
}

func (program Program) participantsScreen(chat database.GetChatChat) error {
	for {
		clearScreen()

		fmt.Printf("%s: %s\n", chat.Title, chat.Description)

		participants, err := program.database.GetParticipants(program.context, chat.ChatID)
		if err != nil {
			return fmt.Errorf("failed to get participants: %w", err)
		}

		if len(participants) == 0 {
			fmt.Println("No participants")
			fmt.Print("Press enter to return...")
			_, err := program.readInput()
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}
			return nil
		}

		orderedParticipants := make([]string, 0, len(participants))
		for _, participant := range participants {
			orderedParticipants = append(orderedParticipants, string(participant.PublicIdentityKey))
			fmt.Printf("%d. %s\n", len(orderedParticipants), participant.Name)
		}

		fmt.Printf("Enter participant number (or %d to go back): ", len(participants)+1)
		participantNumber, err := program.readInput()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		action, err := strconv.ParseUint(participantNumber, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse participant number: %w", err)
		}

		if action == uint64(len(participants)+1) {
			return nil
		}

		err = program.updateParticipantScreen(chat, participants[orderedParticipants[action-1]])
		if err != nil {
			return fmt.Errorf("update participant screen error: %w", err)
		}
	}
}

func (program Program) updateParticipantScreen(chat database.GetChatChat, participant *database.Participant) error {
	clearScreen()

	fmt.Print("Name: ")
	name, err := program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if name == "" {
		name = participant.Name
	}

	err = program.database.UpdateParticipant(program.context, database.UpdateParticipantParams{
		ChatID:           chat.ChatID,
		SequenceNumber:   participant.SequenceNumber,
		Name:             name,
		EcdhPublicKey:    participant.EcdhPublicKey,
		MyEcdhPrivateKey: participant.MyEcdhPrivateKey,
	})
	if err != nil {
		return fmt.Errorf("failed to update participant: %w", err)
	}

	return nil
}

func (program Program) fetchLatestMessages(chat database.GetChatChat) error {
	latestMessages, err := receiveMessages(chat.PrivateIdentityKey)
	if err != nil {
		return fmt.Errorf("failed to receive messages: %w", err)
	}

	for _, message := range latestMessages {
		if bytes.Equal(message.FromPublicIdentityKey, chat.PrivateIdentityKey.Public().(ed25519.PublicKey)) {
			continue
		}

		participants, err := program.database.GetParticipants(program.context, chat.ChatID)
		if err != nil {
			return fmt.Errorf("failed to get participants: %w", err)
		}

		participantInfo := participants[string(message.FromPublicIdentityKey)]

		signature := message.Data[:ed25519.SignatureSize]
		encryptedPayload := message.Data[ed25519.SignatureSize:]

		signatureValid := ed25519.Verify(participantInfo.PublicIdentityKey, encryptedPayload, signature)
		if !signatureValid {
			return fmt.Errorf("signature '%s' invalid for public identity key '%s'", hex.EncodeToString(signature), hex.EncodeToString(participantInfo.PublicIdentityKey))
		}

		secretKey, err := x25519.ECDH(participantInfo.MyEcdhPrivateKey, participantInfo.EcdhPublicKey)
		if err != nil {
			return fmt.Errorf("failed to create secret key: %w", err)
		}

		payload, err := xchacha20poly1305.Decrypt(encryptedPayload, secretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt payload: %w", err)
		}

		messageSequenceNumber, err := program.database.GetNextSequenceNumber(program.context, chat.ChatID)
		if err != nil {
			return fmt.Errorf("failed to get next sequence number: %w", err)
		}

		content := string(payload[x25519.PublicKeySize:])
		err = program.database.CreateMessage(program.context, database.CreateMessageParams{
			ChatID:            chat.ChatID,
			SequenceNumber:    messageSequenceNumber,
			PublicIdentityKey: message.FromPublicIdentityKey,
			Content:           content,
			CreatedAt:         time.Unix(message.CreatedAt, 0),
		})
		if err != nil {
			return fmt.Errorf("failed to create message: %w", err)
		}

		participantNewEcdhPublicKey, err := x25519.PublicKeyFromBytes(payload[:x25519.PublicKeySize])
		if err != nil {
			return fmt.Errorf("failed to create public key: %w", err)
		}

		err = program.database.UpdateParticipant(program.context, database.UpdateParticipantParams{
			ChatID:           chat.ChatID,
			SequenceNumber:   participantInfo.SequenceNumber,
			Name:             participantInfo.Name,
			EcdhPublicKey:    participantNewEcdhPublicKey,
			MyEcdhPrivateKey: participantInfo.MyEcdhPrivateKey,
		})
		if err != nil {
			return fmt.Errorf("failed to update participant: %w", err)
		}
	}

	return nil
}

func (program Program) messagesScreen(chat database.GetChatChat) error {
	clearScreen()

	err := program.fetchLatestMessages(chat)
	if err != nil {
		return fmt.Errorf("failed to fetch latest messages: %w", err)
	}

	messages, err := program.database.GetMessages(program.context, chat.ChatID)
	if err != nil {
		return fmt.Errorf("failed to get messages: %w", err)
	}

	fmt.Printf("%s: %s\n", chat.Title, chat.Description)

	if len(messages) == 0 {
		fmt.Println("No messages")
		fmt.Print("Press enter to return...")
		_, err := program.readInput()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		return nil
	}

	participants, err := program.database.GetParticipants(program.context, chat.ChatID)
	if err != nil {
		return fmt.Errorf("failed to get participants: %w", err)
	}

	for _, message := range messages {
		var participantName string
		if bytes.Equal(message.PublicIdentityKey, chat.PrivateIdentityKey.Public().(ed25519.PublicKey)) {
			participantName = "You"
		} else {
			participantName = participants[string(message.PublicIdentityKey)].Name
		}

		fmt.Printf("(%s) %s\n", participantName, message.Content)
	}

	fmt.Print("\nPress enter to return...")
	_, err = program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	return nil
}

func (program Program) sendMessageScreen(chat database.GetChatChat) error {
	clearScreen()

	fmt.Print("Message: ")
	message, err := program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	for {
		participants, err := program.database.GetParticipants(program.context, chat.ChatID)
		if err != nil {
			return fmt.Errorf("failed to get participants: %w", err)
		}

		messagesToSend := make([]SendMessage, 0, len(participants))
		newMyEcdhPrivateKeys := make(map[string]*x25519.PrivateKey, len(participants))
		for _, participant := range participants {
			secretKey, err := x25519.ECDH(participant.MyEcdhPrivateKey, participant.EcdhPublicKey)
			if err != nil {
				return fmt.Errorf("failed to create secret key: %w", err)
			}

			newEcdhPublicKey, newEcdhPrivateKey := x25519.Generate()

			newMyEcdhPrivateKeys[string(participant.PublicIdentityKey)] = newEcdhPrivateKey

			payload := bytes.Buffer{}
			payload.Write(newEcdhPublicKey.Bytes())
			payload.WriteString(message)

			encryptedPayload, err := xchacha20poly1305.Encrypt(payload.Bytes(), secretKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt payload: %w", err)
			}

			signature := ed25519.Sign(chat.PrivateIdentityKey, encryptedPayload)
			encryptedPayload = append(signature, encryptedPayload...)

			messagesToSend = append(messagesToSend, SendMessage{
				ToPublicIdentityKey: participant.PublicIdentityKey,
				Data:                encryptedPayload,
			})
		}

		index, err := program.database.GetNextSequenceNumber(program.context, chat.ChatID)
		if err != nil {
			return fmt.Errorf("failed to get next sequence number: %w", err)
		}

		data := SendMessagesData{
			Messages: messagesToSend,
			Index:    uint64(index),
		}

		retry, err := sendMessages(chat.PrivateIdentityKey, data)
		if err != nil {
			if retry {
				err := program.fetchLatestMessages(chat)
				if err != nil {
					return fmt.Errorf("failed to fetch latest messages: %w", err)
				}

				continue
			}

			return fmt.Errorf("failed to send messages: %w", err)
		}

		err = program.database.CreateMessage(program.context, database.CreateMessageParams{
			ChatID:            chat.ChatID,
			SequenceNumber:    index,
			PublicIdentityKey: chat.PrivateIdentityKey.Public().(ed25519.PublicKey),
			Content:           message,
			CreatedAt:         time.Now(),
		})
		if err != nil {
			return fmt.Errorf("failed to create message: %w", err)
		}

		for _, participant := range participants {
			err = program.database.UpdateParticipant(program.context, database.UpdateParticipantParams{
				ChatID:           chat.ChatID,
				SequenceNumber:   participant.SequenceNumber,
				Name:             participant.Name,
				EcdhPublicKey:    participant.EcdhPublicKey,
				MyEcdhPrivateKey: newMyEcdhPrivateKeys[string(participant.PublicIdentityKey)],
			})
			if err != nil {
				return fmt.Errorf("failed to update participant: %w", err)
			}
		}

		return nil
	}
}

func (program Program) createChatScreen() error {
	clearScreen()

	fmt.Print("Title: ")
	title, err := program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	fmt.Print("Description: ")
	description, err := program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	fmt.Print("Number of other participants: ")
	numOtherParticipantsString, err := program.readInput()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	numOtherParticipants, err := strconv.ParseUint(numOtherParticipantsString, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse number of other participants: %w", err)
	}

	publicIdentityKey, privateIdentityKey, err := ed25519.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	type ParticipantInfo struct {
		SequenceNumber    uint64
		PublicIdentityKey ed25519.PublicKey
		EcdhPublicKey     *x25519.PublicKey
		MyEcdhPrivateKey  *x25519.PrivateKey
		Name              string
	}

	participantsPublicIdentityKeys := make([][]byte, 0, numOtherParticipants)
	participants := make(map[string]*ParticipantInfo, numOtherParticipants)
	for i := uint64(0); i < numOtherParticipants; i++ {
		ecdhPublicKey, ecdhPrivateKey := x25519.Generate()

		myPublicHandshakeInfo := fmt.Sprintf("%x%x", publicIdentityKey, ecdhPublicKey.Bytes())
		fmt.Println("My public handshake info:", myPublicHandshakeInfo)

		fmt.Printf("Participant %d public handshake info: ", i+1)
		action, err := program.readInput()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		fmt.Print("Name: ")
		name, err := program.readInput()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		participantPublicHandshakeInfo, err := hex.DecodeString(action)
		if err != nil {
			return fmt.Errorf("failed to decode participant public handshake info: %w", err)
		}

		if len(participantPublicHandshakeInfo) != ed25519.PublicKeySize+x25519.PublicKeySize {
			return fmt.Errorf("invalid length of participant public handshake info")
		}

		participantPublicIdentityKey := participantPublicHandshakeInfo[:ed25519.PublicKeySize]
		participantEcdhPublicKeyBytes := participantPublicHandshakeInfo[ed25519.PublicKeySize:]

		participantEcdhPublicKey, err := x25519.PublicKeyFromBytes(participantEcdhPublicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse participant ecdh public key: %w", err)
		}

		participantsPublicIdentityKeys = append(participantsPublicIdentityKeys, participantPublicIdentityKey)

		participants[string(participantPublicIdentityKey)] = &ParticipantInfo{
			SequenceNumber:    i,
			PublicIdentityKey: participantPublicIdentityKey,
			EcdhPublicKey:     participantEcdhPublicKey,
			MyEcdhPrivateKey:  ecdhPrivateKey,
			Name:              name,
		}
	}

	err = register(privateIdentityKey, RegisterData{
		PublicIdentityKeys: participantsPublicIdentityKeys,
	})
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	chatId, err := program.database.CreateChat(program.context, database.CreateChatParams{
		PrivateIdentityKey: privateIdentityKey,
		Title:              title,
		Description:        description,
	})
	if err != nil {
		return fmt.Errorf("failed to create chat: %w", err)
	}

	for _, participant := range participants {
		err = program.database.CreateParticipant(program.context, database.CreateParticipantParams{
			ChatID:            chatId,
			SequenceNumber:    int64(participant.SequenceNumber),
			PublicIdentityKey: participant.PublicIdentityKey,
			Name:              participant.Name,
			EcdhPublicKey:     participant.EcdhPublicKey,
			MyEcdhPrivateKey:  participant.MyEcdhPrivateKey,
		})
		if err != nil {
			return fmt.Errorf("failed to create participant: %w", err)
		}
	}

	err = program.chatScreen(chatId)
	if err != nil {
		return fmt.Errorf("chat screen error: %w", err)
	}

	return nil
}
