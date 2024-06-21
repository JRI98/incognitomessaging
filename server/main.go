package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/JRI98/yeomessaging/internal/ed25519"
	"github.com/JRI98/yeomessaging/server/handlers"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	slogecho "github.com/samber/slog-echo"
)

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	handler, err := handlers.NewHandler()
	if err != nil {
		slog.Error("Could not initialize handler", slog.Any("err", err))
		os.Exit(1)
	}
	defer handler.Cleanup()

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Validator = &CustomValidator{validator: validator.New()}
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			// slog.Error("HTTPErrorHandler response commited error", slog.Any("error", err))
			return
		}

		httpError, ok := err.(*echo.HTTPError)
		if !ok {
			httpError = echo.NewHTTPError(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)).SetInternal(err)
		}

		var sendError error
		if c.Request().Method == http.MethodHead {
			sendError = c.NoContent(httpError.Code)
		} else {
			sendError = c.String(httpError.Code, fmt.Sprint(httpError.Message))
		}

		if sendError != nil {
			slog.Error("HTTPErrorHandler send error", slog.Any("sendError", sendError), slog.Any("httpError", httpError))
		}
	}

	e.Use(slogecho.NewWithConfig(slog.Default(), slogecho.Config{
		DefaultLevel:     slog.LevelInfo,
		ClientErrorLevel: slog.LevelWarn,
		ServerErrorLevel: slog.LevelError,
		WithUserAgent:    true,
		WithRequestID:    true,
		WithRequestBody:  true,
	}))

	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		DisableStackAll: true,
		LogErrorFunc: func(c echo.Context, err error, stack []byte) error {
			return fmt.Errorf("[PANIC RECOVER] %v\n%s", err, stack)
		},
		DisableErrorHandler: true,
	}))

	e.Use(middleware.RequestID())

	e.Use(middleware.Secure())

	e.Use(middleware.CORS())

	api := e.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authorizationHeader := c.Request().Header.Get(echo.HeaderAuthorization)
			base64Decoded, err := base64.StdEncoding.DecodeString(authorizationHeader)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			}

			if len(base64Decoded) != ed25519.PublicKeySize+ed25519.SignatureSize {
				return echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			}

			publicKeyBytes := base64Decoded[:ed25519.PublicKeySize]
			bodySignature := base64Decoded[ed25519.PublicKeySize:]

			publicKey, err := ed25519.PublicKeyFromBytes(publicKeyBytes)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			}

			body, err := io.ReadAll(c.Request().Body)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			}
			c.Request().Body.Close()

			c.Request().Body = io.NopCloser(bytes.NewReader(body))

			validSignature := ed25519.Verify(publicKey, body, bodySignature)
			if !validSignature {
				return echo.NewHTTPError(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			}

			c.Set("publicKey", publicKey)

			return next(c)
		}
	})

	api.POST("/register", handler.Register)
	api.GET("/messages", handler.ReceiveMessages)
	api.POST("/messages", handler.SendMessages)

	go func() {
		port := os.Getenv("PORT")
		if port == "" {
			port = "3000"
		}

		if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
			slog.Error("Server start error", slog.Any("err", err))
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		slog.Error("Server shutdown error", slog.Any("err", err))
	} else {
		slog.Info("Server successfully shutdown")
	}
}
