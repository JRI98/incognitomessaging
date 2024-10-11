# Incognito Messaging

Implementation of an end-to-end encrypted messaging service. Loosely inspired by [Signal](https://signal.org/docs) but trying to be simpler by keeping the messages ordered in the server. Makes use of [NATS](https://nats.io) in the server and [SQLite](https://www.sqlite.org/) to store the messages locally.

## SQL

`sqlc generate -f client/database/sqlc.yaml`

## Server

`docker run -p 4222:4222 -it nats -js`
`go run server/main.go`

## Client

`go run client/main.go`

## Future Research

- RFC9420: <https://datatracker.ietf.org/doc/rfc9420/>
