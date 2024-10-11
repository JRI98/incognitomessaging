package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/JRI98/incognitomessaging/internal/ed25519"
	"github.com/JRI98/incognitomessaging/server/services"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	NATSService *services.NATSService
}

func NewHandler() (*Handler, error) {
	natsService, err := services.NewNATSService()
	if err != nil {
		return nil, fmt.Errorf("could not create NATS service: %w", err)
	}

	return &Handler{
		NATSService: natsService,
	}, nil
}

func (h *Handler) Cleanup() {
	h.NATSService.Close()
}

func validateData[T any](c echo.Context) (*T, error) {
	res := new(T)

	if err := c.Bind(res); err != nil {
		return nil, err
	}

	if err := c.Validate(res); err != nil {
		return nil, err
	}

	return res, nil
}

func getPublicKey(c echo.Context) ed25519.PublicKey {
	publicKey, ok := c.Get("publicKey").(ed25519.PublicKey)
	if !ok {
		panic(errors.New("could not get public key from context"))
	}

	return publicKey
}

func newEchoHTTPError(code int, message string, err *error) *echo.HTTPError {
	if err != nil {
		return echo.NewHTTPError(code, message).SetInternal(*err)
	}
	return echo.NewHTTPError(code, message)
}

type RegisterData struct {
	PublicIdentityKeys [][]byte `json:"public_identity_keys" validate:"required"`
}

func (h *Handler) Register(c echo.Context) error {
	publicKey := getPublicKey(c)

	data, err := validateData[RegisterData](c)
	if err != nil {
		return fmt.Errorf("could not validate data: %w", err)
	}

	err = h.NATSService.Register(c.Request().Context(), publicKey, data.PublicIdentityKeys)
	if err != nil {
		return newEchoHTTPError(http.StatusInternalServerError, "Could not register", &err)
	}

	return c.NoContent(http.StatusOK)
}

func (h *Handler) ReceiveMessages(c echo.Context) error {
	publicKey := getPublicKey(c)

	messages, err := h.NATSService.ReceiveMessages(c.Request().Context(), publicKey)
	if err != nil {
		return newEchoHTTPError(http.StatusInternalServerError, "Could not receive messages", &err)
	}

	return c.JSON(http.StatusOK, messages)
}

type Message struct {
	ToPublicIdentityKey []byte `json:"to_public_identity_key" validate:"required"`
	Data                []byte `json:"data" validate:"required"`
}

type SendMessagesData struct {
	Messages []Message `json:"messages" validate:"required"`
	Index    *uint64   `json:"index" validate:"required"`
}

func (h *Handler) SendMessages(c echo.Context) error {
	publicKey := getPublicKey(c)

	data, err := validateData[SendMessagesData](c)
	if err != nil {
		return fmt.Errorf("could not validate data: %w", err)
	}

	data.Messages = append(data.Messages, Message{ToPublicIdentityKey: publicKey, Data: []byte{}})

	// Check for duplicate destinations
	toPublicIdentityKeyToMessage := make(map[string]Message, len(data.Messages))
	for _, message := range data.Messages {
		toPublicIdentityKey := string(message.ToPublicIdentityKey)
		if _, ok := toPublicIdentityKeyToMessage[toPublicIdentityKey]; ok {
			return newEchoHTTPError(http.StatusBadRequest, "Duplicate message destination", nil)
		}
		toPublicIdentityKeyToMessage[toPublicIdentityKey] = message
	}

	// Sort messages by public identity key
	slices.SortFunc(data.Messages, func(a, b Message) int {
		return slices.Compare(a.ToPublicIdentityKey, b.ToPublicIdentityKey)
	})

	for _, message := range data.Messages {
		err = h.NATSService.SendMessage(c.Request().Context(), publicKey, message.ToPublicIdentityKey, message.Data, *data.Index)
		if err != nil {
			if errors.Is(err, services.ErrWrongMessageIndex) {
				return newEchoHTTPError(http.StatusConflict, "Wrong message index", &err)
			}
			return newEchoHTTPError(http.StatusInternalServerError, "Could not send message", &err)
		}
	}

	return c.NoContent(http.StatusOK)
}
