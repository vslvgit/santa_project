package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var db *pgxpool.Pool

// Подключение к PostgreSQL
func ConnectDB() {
	dsn := "postgres://opsoop:passwordPSWD@localhost:5432/santa_project"
	var err error

	db, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	// Устанавливаем таймауты
	db.Config().MaxConnIdleTime = 5 * time.Minute
	db.Config().MaxConns = 10

	fmt.Println("Connected to PostgreSQL")
}
