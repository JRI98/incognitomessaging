package database

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/JRI98/yeomessaging/client/database/queries"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var ddl string

type Database struct {
	db            *sql.DB
	queries       *queries.Queries
	encryptionKey []byte
}

func Open(databasePath string) (*Database, error) {
	ctx := context.Background()

	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, err
	}

	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return nil, err
	}

	qs := queries.New(db)

	return &Database{db: db, queries: qs}, nil
}

func (database *Database) SetEncryptionKey(privateKey []byte) error {
	if database.encryptionKey != nil {
		return fmt.Errorf("encryption key already set")
	}
	database.encryptionKey = privateKey

	return nil
}

func (database *Database) WithTx(f func(transaction *Database) error) error {
	tx, err := database.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	qtx := database.queries.WithTx(tx)

	err = f(&Database{db: nil, queries: qtx, encryptionKey: database.encryptionKey})
	if err != nil {
		return fmt.Errorf("failed to execute transaction: %w", err)
	}

	return tx.Commit()
}

func (database *Database) Close() error {
	return database.db.Close()
}
