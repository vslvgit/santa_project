package main

// Структура пользователя
type User struct {
	ID              int      `json:"id"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	Preferences     string   `json:"preferences"`
	Password        string   `json:"password"`
	CompletedEvents []string `json:"completed_events"`
}
