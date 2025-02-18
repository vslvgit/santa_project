package main

import "github.com/golang-jwt/jwt/v5"

type Lobby struct {
	LobbyCode string `json:"lobby_code"`
	LobbyName string `json:"lobby_name"`
	IsStarted bool   `json:"is_started"`
}

// Структура для JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}
