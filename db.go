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

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("Unable to parse database config: %v\n", err)
	}

	// Устанавливаем таймауты и ограничения
	config.MaxConnIdleTime = 5 * time.Minute
	config.MaxConns = 10

	// Создаем пул соединений
	db, err = pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	fmt.Println("Connected to PostgreSQL")
}
