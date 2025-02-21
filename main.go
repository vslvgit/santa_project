package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func main() {

	ConnectDB()
	defer db.Close()

	r := chi.NewRouter()

	// Маршруты
	r.Post("/api/v1/register", registerUser)
	r.Post("/api/v1/login", loginUser)
	r.Post("/api/v1/logout", logoutUser)
	r.Get("/api/v1/user", getUser)
	r.Patch("/api/v1/user", updateUser)

	// Защищённый маршрут
	r.Route("/api", func(r chi.Router) {
		r.Use(jwtMiddleware)                   // Подключаем JWT Middleware
		r.Get("/protected", protectedEndpoint) // Доступен только с токеном
	})

	// Запуск сервера
	fmt.Println("Server is running on port 8080...")
	http.ListenAndServe(":8080", r)
}
