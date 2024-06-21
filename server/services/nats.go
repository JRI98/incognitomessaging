package services

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type NATSService struct {
	nc *nats.Conn
	js jetstream.JetStream
}

func NewNATSService() (*NATSService, error) {
	natsURL, ok := os.LookupEnv("NATS_URL")
	if !ok {
		natsURL = nats.DefaultURL
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, fmt.Errorf("could not connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("could not connect to NATS JetStream: %w", err)
	}

	return &NATSService{
		nc: nc,
		js: js,
	}, nil
}

func (s *NATSService) Register(ctx context.Context, publicIdentityKey []byte, identityKeys [][]byte) error {
	subjects := make([]string, 0, len(identityKeys))

	identityKeys = append(identityKeys, publicIdentityKey)
	for _, identityKey := range identityKeys {
		subjects = append(subjects, fmt.Sprintf("MESSAGES.%x.%x", identityKey, publicIdentityKey))
	}

	stream, err := s.js.CreateStream(ctx, jetstream.StreamConfig{
		Name:      fmt.Sprintf("MESSAGES_%x", publicIdentityKey),
		Subjects:  subjects,
		Retention: jetstream.WorkQueuePolicy,
	})
	if err != nil {
		return fmt.Errorf("could not create stream: %w", err)
	}

	_, err = stream.CreateConsumer(ctx, jetstream.ConsumerConfig{
		Name:      fmt.Sprintf("MESSAGES_%x", publicIdentityKey),
		Durable:   fmt.Sprintf("MESSAGES_%x", publicIdentityKey),
		AckPolicy: jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("could not create consumer: %w", err)
	}

	return nil
}

type Message struct {
	FromPublicIdentityKey []byte `json:"from_public_identity_key"`
	Data                  []byte `json:"data"`
	CreatedAt             int64  `json:"created_at"`
}

func (s *NATSService) ReceiveMessages(ctx context.Context, publicIdentityKey []byte) ([]Message, error) {
	stream, err := s.js.Stream(ctx, fmt.Sprintf("MESSAGES_%x", publicIdentityKey))
	if err != nil {
		return nil, fmt.Errorf("could not get stream: %w", err)
	}

	consumer, err := stream.Consumer(ctx, fmt.Sprintf("MESSAGES_%x", publicIdentityKey))
	if err != nil {
		return nil, fmt.Errorf("could not get consumer: %w", err)
	}

	messages, err := consumer.FetchNoWait(20)
	if err != nil {
		return nil, fmt.Errorf("could not fetch messages: %w", err)
	}

	messagesResponse := make([]Message, 0, 20)
	for msg := range messages.Messages() {
		fromString, err := hex.DecodeString(strings.Split(msg.Subject(), ".")[1])
		if err != nil {
			return nil, fmt.Errorf("could not decode from string: %w", err)
		}

		metadata, err := msg.Metadata()
		if err != nil {
			return nil, fmt.Errorf("could not get metadata: %w", err)
		}

		messagesResponse = append(messagesResponse, Message{
			FromPublicIdentityKey: fromString,
			Data:                  msg.Data(),
			CreatedAt:             metadata.Timestamp.Unix(),
		})
		err = msg.Ack()
		if err != nil {
			return nil, fmt.Errorf("could not ack message: %w", err)
		}
	}

	return messagesResponse, nil
}

var ErrWrongMessageIndex = fmt.Errorf("wrong message index")

func (s *NATSService) SendMessage(ctx context.Context, fromPublicIdentityKey []byte, toPublicIdentityKey []byte, data []byte, messageIndex uint64) error {
	_, err := s.js.Publish(ctx, fmt.Sprintf("MESSAGES.%x.%x", fromPublicIdentityKey, toPublicIdentityKey), data, jetstream.WithExpectLastSequence(messageIndex))
	if err != nil {
		if strings.Contains(err.Error(), "wrong last sequence") {
			return ErrWrongMessageIndex
		}
		return fmt.Errorf("could not publish message: %w", err)
	}

	return nil
}

func (s *NATSService) Close() {
	s.nc.Close()
}
