package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	// "golang.org/x/crypto/bcrypt"
)

// Простая база данных (in-memory)
var users = make(map[string]User)
var mu sync.Mutex

// Секретный ключ для подписи JWT
var jwtSecret = []byte("super_secret_key")

// Функция для генерации JWT-токена
func generateJWT(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // Токен на 24 часа
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Функция для хеширования пароля
// func hashPassword(password string) (string, error) {
// 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	return string(bytes), err
// }

// Функция для проверки пароля
// func checkPassword(hashedPassword, password string) bool {
// 	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
// 	return err == nil
// }

func registerUser(w http.ResponseWriter, r *http.Request) {
	var user User

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Email == "" || user.Password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := users[user.Email]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	users[user.Email] = user

	// Возвращаем успешный ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "User registered successfully",
		"username": user.Username,
	})

	// Хешируем пароль
	// hashedPassword, err := hashPassword(user.Password)
	// if err != nil {
	// 	http.Error(w, "Error hashing password", http.StatusInternalServerError)
	// 	return
	// }

	// Сохраняем пользователя в базу
	// _, err = db.Exec(context.Background(), "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", user.Username, user.Email, hashedPassword)
	// if err != nil {
	// 	http.Error(w, "User already exists", http.StatusConflict)
	// 	return
	// }

	// w.WriteHeader(http.StatusCreated)
	// json.NewEncoder(w).Encode(map[string]string{
	// 	"message": "User registered successfully",
	// })

}

// Обработчик входа (логина)
func loginUser(w http.ResponseWriter, r *http.Request) {
	var creds User

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	user, exists := users[creds.Email]
	mu.Unlock()

	if !exists || user.Password != creds.Password {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	// Ищем пользователя в базе
	//	var storedPassword string
	//	err := db.QueryRow(context.Background(), "SELECT password FROM users WHERE email=$1", creds.Email).Scan(&storedPassword)
	//	if err != nil {
	//		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
	//		return
	//	}

	// Проверяем пароль
	//	if !checkPassword(storedPassword, creds.Password) {
	//		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
	//		return
	//	}

	token, err := generateJWT(user.Email)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}

func logoutUser(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Unix(0, 0), // Устанавливаем в прошлое время
		HttpOnly: true,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

func getUser(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := authHeader[len("Bearer "):]
	claims := &jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Получаем email из токена
	email, ok := (*claims)["email"].(string)
	if !ok {
		http.Error(w, "Invalid token payload", http.StatusUnauthorized)
		return
	}

	// Ищем пользователя в памяти
	mu.Lock()
	user, exists := users[email]
	mu.Unlock()

	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Формируем ответ
	response := map[string]interface{}{
		"id":               user.ID,
		"username":         user.Username,
		"name":             user.Username, // Временно используем `username` как `name`
		"preferences":      "{}",          // Заглушка для предпочтений
		"completed_events": []string{},    // Заглушка для завершенных событий
	}

	// Отправляем JSON-ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

func updateUser(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPatch {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Получаем заголовок Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Извлекаем токен
	tokenString := authHeader[len("Bearer "):]
	claims := &jwt.MapClaims{}

	// Парсим токен
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Получаем email из токена
	email, ok := (*claims)["email"].(string)
	if !ok {
		http.Error(w, "Invalid token payload", http.StatusUnauthorized)
		return
	}

	// Ищем пользователя в памяти
	mu.Lock()
	user, exists := users[email]
	mu.Unlock()

	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Декодируем JSON-запрос
	var updateData struct {
		Name        string `json:"name"`
		Preferences string `json:"preferences"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Обновляем данные пользователя (только если поля переданы)
	if updateData.Name != "" {
		user.Username = updateData.Name // Временно используем `Username` как `Name`
	}
	if updateData.Preferences != "" {
		// Здесь можно валидировать JSON `Preferences`
		user.Preferences = updateData.Preferences
	}

	// Сохраняем обновленного пользователя
	mu.Lock()
	users[email] = user
	mu.Unlock()

	// Возвращаем обновленные данные
	response := map[string]interface{}{
		"message":          "User updated successfully",
		"id":               user.ID,
		"username":         user.Username,
		"name":             user.Username, // TODO
		"preferences":      user.Preferences,
		"completed_events": user.CompletedEvents,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Middleware для проверки JWT-токена
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Парсим токен
		tokenString := authHeader[len("Bearer "):]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		// Проверяем валидность токена
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Если токен валиден, передаём управление следующему обработчику
		next.ServeHTTP(w, r)
	})
}

// Защищённый эндпоинт ??
func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Welcome to the protected route!",
	})
}
