package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/go-chi/chi/v5"

	"github.com/gorilla/sessions"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
}

var (
	oauthConfig *oauth2.Config
	store       *sessions.CookieStore
	db          *sqlx.DB
)

func init() {
	// Загружаем переменные окружения из файла .env
	_ = godotenv.Load()

	// Настройки OAuth
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:3000/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// Настройки сессии
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,                // 1 день
		HttpOnly: true,                 // Безопасность куки
		SameSite: http.SameSiteLaxMode, // Либо http.SameSiteStrictMode
		Secure:   false,                // Используйте true в продакшене, если у вас HTTPS
	}

	// Подключение к базе данных PostgreSQL через sqlx
	var err error
	connStr := os.Getenv("DATABASE_URL")
	db, err = sqlx.Connect("postgres", connStr)
	if err != nil {
		log.Fatalln("Не удалось подключиться к базе данных:", err)
	}
}
func main() {
	r := chi.NewRouter()

	r.Get("/", homeHandler)
	r.Get("/auth/google", googleLoginHandler)
	r.Get("/auth/google/callback", googleCallbackHandler)
	r.Get("/dashboard", dashboardHandler)
	r.Get("/logout", logoutHandler)
	r.Get("/users/{id}", getUserHandler)

	port := "3000"
	fmt.Println("Сервер запущен на порту:", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Извлекаем ID пользователя из URL
	userID := chi.URLParam(r, "id")

	// Ищем данные пользователя в базе данных
	var user User
	err := db.Get(&user, "SELECT id, name, email FROM users WHERE id = $1", userID)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	}

	// Возвращаем данные пользователя в формате JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, "Ошибка при сериализации данных", http.StatusInternalServerError)
		return
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "templates/index.html")
}

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL("random-state-string", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Не удалось получить код авторизации", http.StatusBadRequest)
		return
	}

	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println("Ошибка обмена кода на токен:", err)
		http.Error(w, "Ошибка обмена кода на токен", http.StatusInternalServerError)
		return
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		log.Println("Ошибка получения информации о пользователе:", err)
		http.Error(w, "Ошибка получения информации о пользователе", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Println("Ошибка декодирования JSON:", err)
		http.Error(w, "Ошибка декодирования JSON", http.StatusInternalServerError)
		return
	}

	// Сохранение данных пользователя в базу данных
	_, err = db.Exec(`INSERT INTO users (name, email, password) VALUES ($1, $2, $3)
		ON CONFLICT (email) DO UPDATE SET name = $1, email = $2, password = $3`,
		user.Name, user.Email, user.Password)

	if err != nil {
		log.Println("Ошибка при сохранении данных пользователя в базе:", err)
		http.Error(w, "Ошибка сохранения данных пользователя", http.StatusInternalServerError)
		return
	}

	// Сериализуем пользователя в JSON
	userJSON, err := json.Marshal(user)
	if err != nil {
		log.Println("Ошибка сериализации данных пользователя:", err)
		http.Error(w, "Ошибка сериализации данных пользователя", http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "auth-session")
	session.Values["user"] = string(userJSON)

	// Логируем данные перед сохранением
	log.Println("Данные пользователя:", user)

	err = session.Save(r, w)
	if err != nil {
		log.Println("Ошибка сохранения сессии:", err)
		http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
		return
	}

	log.Println("Сессия успешно сохранена. Перенаправление на /dashboard")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	userJSON, ok := session.Values["user"].(string) // Извлекаем JSON строку
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var user User
	if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
		log.Println("Ошибка десериализации данных пользователя:", err)
		http.Error(w, "Ошибка десериализации данных пользователя", http.StatusInternalServerError)
		return
	}
	tmpl, _ := os.ReadFile("templates/dashboard.html")
	_, _ = w.Write(tmpl)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
