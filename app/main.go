package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	secret        = "OhsneGhatghJdfrtbpprstxu887b3gaq"
	secretForpass = "jnskHjsiwngw7bfi0037gbfjwlmfiGKV"
)

type Message struct {
	Code int    `json:"code"`
	Text string `json:"message"`
}

type usermodel struct {
	ID       int32
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string
}

type actor struct {
	Name        string `json:"name"`
	Gender      string `json:"gender"`
	DateOfBirth string `json:"birth_date"`
}

type actor_name struct {
	Name string `json:"name"`
}

type actor_resp struct {
	Actors []actor_films `json:"actors"`
}

type actor_films struct {
	Name        string   `json:"name"`
	Gender      string   `json:"gender"`
	DateOfBirth string   `json:"birth_date"`
	Films       []string `json:"films"`
}

type films_resp struct {
	Films []film `json:"films"`
}

type film struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	ProductionDate string   `json:"production_date"`
	Rate           float32  `json:"rate"`
	Actors         []string `json:"actors"`
}

type film_name struct {
	Name string `json:"name"`
}

type sort struct {
	Sort string `json:"sort_by"`
}

func main() {
	logger := log.New(os.Stdout, "HTTP: ", log.Ldate|log.Ltime)
	db := initDatabase("postgres", "postgres", "database:5432", "filmoteka")

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(db)

	http.HandleFunc("/actors", verifyHandler(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		switch r.Method {
		case http.MethodPost:
			var req actor
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				writeToResponse(w, Message{400, "Failed to parse JSON request body"}, http.StatusBadRequest, logger)
				logger.Printf("Failed to parse request: %v\n", err)
				return
			}
			name := req.Name
			gender := req.Gender
			birthDate := req.DateOfBirth
			if name == "" {
				writeToResponse(w, Message{422, "Name is required"}, 422, logger)
				return
			}
			if gender == "" {
				writeToResponse(w, Message{422, "Gender is required"}, 422, logger)
				return
			}
			if birthDate == "" {
				writeToResponse(w, Message{422, "Birth date is required"}, 422, logger)
				return
			}

			addActor(req.Name, req.Gender, req.DateOfBirth, db, logger, w)
		case http.MethodDelete:
			var req actor_name
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				writeToResponse(w, Message{400, "Failed to parse JSON request body"}, http.StatusBadRequest, logger)
				logger.Printf("Failed to parse request: %v\n", err)
				return
			}

			name := req.Name
			if name == "" {
				writeToResponse(w, Message{422, "Name is required"}, 422, logger)
				return
			}

			deleteActor(name, db, logger, w)
		case http.MethodGet:
			getActors(db, logger, w)
		default:
			writeToResponse(w, Message{Code: 405, Text: "Method is not allowed"}, http.StatusMethodNotAllowed, logger)
		}
	}))

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		registerHandler(w, r, db, logger)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		loginHandler(w, r, db, logger)
	})

	http.HandleFunc("/actors/", verifyHandler(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		switch r.Method {
		case http.MethodPost:
			updateActor(w, r, db, logger)
		default:
			writeToResponse(w, Message{Code: 405, Text: "Method is not allowed"}, http.StatusMethodNotAllowed, logger)
		}
	}))

	http.HandleFunc("/films", verifyHandler(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		switch r.Method {
		case http.MethodPost:
			var req film
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				writeToResponse(w, Message{400, "Failed to parse JSON request body"}, http.StatusBadRequest, logger)
				logger.Printf("Failed to parse request: %v\n", err)
				return
			}
			name := req.Name
			description := req.Description
			rate := req.Rate
			releaseDate := req.ProductionDate
			actors := req.Actors
			if name == "" {
				writeToResponse(w, Message{422, "Name cannot be empty"}, 422, logger)
				return
			}
			if rate > 10 || rate < 1 {
				writeToResponse(w, Message{422, "Rate should be between 1 and 10"}, 422, logger)
				return
			}
			if releaseDate == "" {
				writeToResponse(w, Message{422, "Release date is required"}, 422, logger)
				return
			}
			if len(actors) == 0 {
				writeToResponse(w, Message{422, "Actors is required"}, 422, logger)
				return
			}

			addFilm(name, description, releaseDate, rate, actors, db, logger, w)
		case http.MethodDelete:
			var req film_name
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				writeToResponse(w, Message{400, "Failed to parse JSON request body"}, http.StatusBadRequest, logger)
				logger.Printf("Failed to parse request: %v\n", err)
				return
			}

			name := req.Name
			if name == "" {
				writeToResponse(w, Message{422, "Name is required"}, 422, logger)
				return
			}

			deleteFilm(name, db, logger, w)
		case http.MethodGet:
			var req sort
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				writeToResponse(w, Message{400, "Failed to parse JSON request body"}, http.StatusBadRequest, logger)
				logger.Printf("Failed to parse request: %v\n", err)
				return
			}

			place := req.Sort
			if place == "" {
				writeToResponse(w, Message{422, "Name is required"}, 422, logger)
				return
			}
			getFilm(place, db, logger, w)
		default:
			writeToResponse(w, Message{Code: 405, Text: "Method is not allowed"}, http.StatusMethodNotAllowed, logger)
		}
	}))

	http.HandleFunc("/films/", verifyHandler(func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("%s %s %s\n", r.Method, r.URL.Path, r.RemoteAddr)
		switch r.Method {
		case http.MethodPost:
			updateFilm(w, r, db, logger)
		default:
			writeToResponse(w, Message{Code: 405, Text: "Method is not allowed"}, http.StatusMethodNotAllowed, logger)
		}
	}))

	fmt.Println("Server is listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func generatePasswordHash(password string) string {
	h := hmac.New(sha256.New, []byte(secretForpass))
	h.Write([]byte(password))
	hashedPassword := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return hashedPassword
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Token is good")
}

func encodeBase64(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func generateSignature(data string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return encodeBase64(h.Sum(nil))
}

func verifyHandler(next http.HandlerFunc) http.HandlerFunc {
	// Extract token from request header
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Token not provided", http.StatusBadRequest)
			return
		}

		// Split token into parts (header, payload, signature)
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			http.Error(w, "Invalid token format", http.StatusBadRequest)
			return

		}

		// Verify signature
		if generateSignature(parts[0][7:]+"."+parts[1]) != parts[2] {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}

		// Decode payload
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "Failed to decode token payload", http.StatusInternalServerError)
			return
		}

		// Extract expiration time from payload
		var claims struct {
			Exp int64 `json:"exp"`
		}
		err = json.Unmarshal(payload, &claims)
		if err != nil {
			http.Error(w, "Failed to parse token claims", http.StatusInternalServerError)
			return
		}

		// Check token expiration
		if time.Now().Unix() > claims.Exp {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}

}

func toJSON(data interface{}) []byte {
	jsonData, _ := json.Marshal(data)
	return jsonData
}

func generateJWT(username string) (string, error) {
	// Create a map to store the claims
	claims := map[string]interface{}{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expiration time (24 hours)
	}

	// Encode the header and payload to base64
	headerPayload := encodeBase64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + encodeBase64(toJSON(claims))

	// Create a signature using HMAC-SHA256
	signature := generateSignature(headerPayload)

	// Combine the header, payload, and signature to form the JWT token
	token := headerPayload + "." + signature

	return token, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, logger *log.Logger) {
	if r.Method != http.MethodPost {
		http.Error(w, "Неправильный метод запроса", http.StatusMethodNotAllowed)
		logger.Printf("Неправильный метод запроса") // Если метод запроса не POST, возвращаем ошибку
		return
	}
	var usermodel1 usermodel
	err := json.NewDecoder(r.Body).Decode(&usermodel1)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		logger.Printf("Invalid request body: %v\n", err)
		return
	}

	var dbUser usermodel
	var exists bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", usermodel1.Username).Scan(&exists)
	if err != nil {
		http.Error(w, "Ошибка при выполнении запроса к базе данных", http.StatusInternalServerError)
		logger.Printf("Database error: %v\n", err) // Если произошла ошибка при выполнении запроса к базе данных, возвращаем ошибку
		return
	}
	if !exists {
		http.Error(w, "Пользователя с таким именем не существует", http.StatusBadRequest)
		logger.Printf("Пользователя с таким именем не существует") // Если пользователь с таким именем уже существует, возвращаем ошибку
		return
	}

	err = db.QueryRow("SELECT id, username, password FROM users WHERE username=$1", usermodel1.Username).Scan(&dbUser.ID, &dbUser.Username, &dbUser.Password)
	if err != nil {
		http.Error(w, "Ошибка при выполнении запроса к базе данных", http.StatusInternalServerError)
		logger.Printf("Database error: %v\n", err)
		return
	}
	if generatePasswordHash(usermodel1.Password) != dbUser.Password {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		logger.Printf("Invalid password")
		return
	}

	token, err := generateJWT(dbUser.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content_Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, logger *log.Logger) {
	if r.Method != http.MethodPost {
		http.Error(w, "Неправильный метод запроса", http.StatusMethodNotAllowed)
		logger.Printf("Неверный код запроса") // Если метод запроса не POST, возвращаем ошибку
		return
	}
	var usermodel1 usermodel
	err := json.NewDecoder(r.Body).Decode(&usermodel1)
	if err != nil {
		http.Error(w, "Ошибка при чтении тела запроса", http.StatusBadRequest)
		logger.Printf("Неверный код запроса %v\n", err) // Если произошла ошибка при чтении тела запроса, возвращаем ошибку
		return
	}
	if usermodel1.Username == "" || usermodel1.Password == "" {
		http.Error(w, "Имя пользователя и пароль должны быть заполнены", http.StatusBadRequest)
		logger.Printf("Имя пользователя и пароль должны быть заполнены") // Если имя пользователя или пароль не заполнены, возвращаем ошибку
		return
	}

	time.Sleep(100)
	// Проверяем уникальность имени пользователя в базе данных
	var exists bool
	row := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)`, usermodel1.Username)
	err = row.Scan(&exists)
	if err != nil {
		return
	}
	if err != nil {
		http.Error(w, "Ошибка при выполнении запроса к базе данных", http.StatusInternalServerError)
		logger.Printf("Database error:%v\n", err)
		return
	}
	if exists {
		http.Error(w, "Пользователь с таким именем уже существует", http.StatusBadRequest)
		logger.Printf("Пользователь с таким именем уже существует") // Если пользователь с таким именем уже существует, возвращаем ошибку
		return
	}

	hashPass := generatePasswordHash(usermodel1.Password)
	// Добавляем нового пользователя в базу данных
	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", usermodel1.Username, hashPass)
	if err != nil {
		http.Error(w, "Ошибка при добавлении пользователя в базу данных", http.StatusInternalServerError)
		logger.Printf("Database error:%v\n", err)
		return
	}

	fmt.Fprintf(w, "Пользователь %s успешно зарегистрирован\n", usermodel1.Username) // Возвращаем сообщение о успешной регистрации пользователя
}

func writeToResponse(w http.ResponseWriter, resp Message, code int, logger *log.Logger) {
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
		logger.Printf("Error marshaling JSON: %v\n", err)
		return
	}
	_, err = w.Write(jsonData)
	if err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		logger.Printf("Error writing response: %v\n", err)
		return
	}
}

func initDatabase(username string, password string, host string, name string) *sql.DB {
	connection := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", username, password, host, name)
	db, err := sql.Open("postgres", connection)
	if err != nil {
		db, err = sql.Open("postgres", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")
		_, err := db.Exec("CREATE database filmoteka")
		if err != nil {
			return nil
		}
	}
	err = db.Close()
	if err != nil {
		return nil
	}
	connection = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", username, password, host, name)
	db, err = sql.Open("postgres", connection)
	rows, err := db.Query("CREATE TABLE IF NOT EXISTS actors (id SERIAL, name VARCHAR(255) PRIMARY KEY NOT NULL UNIQUE, gender VARCHAR(10) NOT NULL, birth_date VARCHAR(20) NOT NULL)")
	if err != nil {
		log.Fatal(err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(rows)

	rows, err = db.Query("CREATE TABLE IF NOT EXISTS films (id SERIAL, name VARCHAR(150) PRIMARY KEY NOT NULL UNIQUE, description VARCHAR(1000), production_date VARCHAR(20) NOT NULL, rate real)")
	if err != nil {
		log.Fatal(err)
	}

	rows, err = db.Query("CREATE TABLE IF NOT EXISTS films_to_actors (film_name VARCHAR(150) NOT NULL, actor_name varchar(255) NOT NULL)")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec("create table if not exists users(id serial, username varchar(50), password varchar(1000), role varchar(100))")
	if err != nil {
		log.Fatal(err)
	}
	r := db.Ping()
	if r != nil {
		log.Fatal("Connection failed")
	}
	return db

}

func addActor(name string, gender string, date_of_birth string, db *sql.DB, logger *log.Logger, w http.ResponseWriter) {
	insertActor := `INSERT INTO actors (name, gender, birth_date)
			VALUES ($1, $2, $3)
			RETURNING id`

	var actorID int
	err := db.QueryRow(insertActor, name, gender, date_of_birth).Scan(&actorID)
	if err != nil {
		writeToResponse(w, Message{Code: 400, Text: "Failed to insert actor into database"}, 400, logger)
		logger.Printf("Error writing to database: %v\n", err)
		return
	}
	writeToResponse(w, Message{Code: 200, Text: "Actor added successfully"}, http.StatusOK, logger)
}

func deleteActor(name string, db *sql.DB, logger *log.Logger, w http.ResponseWriter) {
	sqlStatement := `DELETE FROM films_to_actors WHERE name = $1`

	_, err := db.Exec(sqlStatement, name)
	if err != nil {
		writeToResponse(w, Message{Code: 400, Text: "Failed to delete actor from database"}, 400, logger)
		logger.Printf("Error deleting from database: %v\n", err)
		return
	}

	sqlStatement = `DELETE FROM actors WHERE name = $1`

	_, err = db.Exec(sqlStatement, name)
	if err != nil {
		writeToResponse(w, Message{Code: 400, Text: "Failed to delete actor from database"}, 400, logger)
		logger.Printf("Error deleting from database: %v\n", err)
		return
	}
	writeToResponse(w, Message{Code: 200, Text: "Actor deleted successfully"}, http.StatusOK, logger)
}

func updateActor(w http.ResponseWriter, r *http.Request, db *sql.DB, logger *log.Logger) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 || parts[1] != "actors" {
		writeToResponse(w, Message{404, "Not found"}, http.StatusNotFound, logger)
		logger.Printf("Wrong path: %v\n", r.URL.Path)
		return
	}
	name := parts[2]
	var req actor
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeToResponse(w, Message{400, "Failed to parse JSON request body"}, http.StatusBadRequest, logger)
		logger.Printf("Failed to parse request: %v\n", err)
		return
	}
	new_name := req.Name
	gender := req.Gender
	birthDate := req.DateOfBirth
	if gender != "" {
		update_query := "UPDATE actors SET gender = $1 WHERE name = $2"
		_, err := db.Exec(update_query, gender, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update gender"}, 400, logger)
			logger.Printf("Failed to update gender: %v\n", err)
			return
		}
	}
	if birthDate != "" {
		update_query := "UPDATE actors SET birth_date = $1 WHERE name = $2"
		_, err := db.Exec(update_query, birthDate, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update birth date"}, 400, logger)
			logger.Printf("Failed to update birth date: %v\n", err)
			return
		}
	}
	if new_name != "" {
		update_query := "UPDATE actors SET name = $1 WHERE name = $2"
		_, err := db.Exec(update_query, new_name, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update name"}, 400, logger)
			logger.Printf("Failed to update name: %v\n", err)
			return
		}
	}
	writeToResponse(w, Message{200, "User updated successfully"}, 200, logger)
}

func addFilm(name string, description string, releaseDate string, rate float32, actors []string, db *sql.DB, logger *log.Logger, w http.ResponseWriter) {
	insertFilm := `INSERT INTO films (name, description, production_date, rate)
			VALUES ($1, $2, $3, $4)
			RETURNING id`

	var filmID int
	err := db.QueryRow(insertFilm, name, description, releaseDate, rate).Scan(&filmID)
	if err != nil {
		writeToResponse(w, Message{Code: 400, Text: "Failed to insert film into database"}, 400, logger)
		logger.Printf("Error writing to database: %v\n", err)
		return
	}

	insertDep := `INSERT INTO films_to_actors(film_name, actor_name) values ($1, $2)`
	for i := 0; i < len(actors); i++ {
		_, err := db.Exec(insertDep, name, actors[i])
		if err != nil {
			writeToResponse(w, Message{Code: 400, Text: "Failed to insert film into database"}, 400, logger)
			logger.Printf("Error writing to database: %v\n", err)
			return
		}
	}
	writeToResponse(w, Message{Code: 200, Text: "Film added successfully"}, http.StatusOK, logger)
}

func deleteFilm(name string, db *sql.DB, logger *log.Logger, w http.ResponseWriter) {
	sqlStatement := `DELETE FROM films_to_actors WHERE film_name = $1`

	_, err := db.Exec(sqlStatement, name)
	if err != nil {
		writeToResponse(w, Message{Code: 400, Text: "Failed to delete film from database"}, 400, logger)
		logger.Printf("Error deleting from database: %v\n", err)
		return
	}

	sqlStatement = `DELETE FROM films WHERE name = $1`

	_, err = db.Exec(sqlStatement, name)
	if err != nil {
		writeToResponse(w, Message{Code: 400, Text: "Failed to delete film from database"}, 400, logger)
		logger.Printf("Error deleting from database: %v\n", err)
		return
	}
	writeToResponse(w, Message{Code: 200, Text: "Film deleted successfully"}, http.StatusOK, logger)
}

func updateFilm(w http.ResponseWriter, r *http.Request, db *sql.DB, logger *log.Logger) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 || parts[1] != "films" {
		writeToResponse(w, Message{404, "Not found"}, http.StatusNotFound, logger)
		logger.Printf("Wrong path: %v\n", r.URL.Path)
		return
	}
	name := parts[2]
	var req film
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeToResponse(w, Message{400, "Failed to parse JSON request body"}, http.StatusBadRequest, logger)
		logger.Printf("Failed to parse request: %v\n", err)
		return
	}
	new_name := req.Name
	description := req.Description
	rate := req.Rate
	releaseDate := req.ProductionDate
	actors := req.Actors
	if description != "" {
		update_query := "UPDATE films SET description = $1 WHERE name = $2"
		_, err := db.Exec(update_query, description, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update description"}, 400, logger)
			logger.Printf("Failed to update description: %v\n", err)
			return
		}
	}
	if releaseDate != "" {
		update_query := "UPDATE films SET production_date = $1 WHERE name = $2"
		_, err := db.Exec(update_query, releaseDate, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update release date"}, 400, logger)
			logger.Printf("Failed to update release date: %v\n", err)
			return
		}
	}
	if rate > 1 && rate < 10 {
		update_query := "UPDATE films SET rate = $1 WHERE name = $2"
		_, err := db.Exec(update_query, rate, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update rate"}, 400, logger)
			logger.Printf("Failed to update rate: %v\n", err)
			return
		}
	}
	if len(actors) != 0 {
		delete_query := "DELETE from films_to_actors where film_name = $1"
		_, err := db.Exec(delete_query, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update actors"}, 400, logger)
			logger.Printf("Failed to update actors: %v\n", err)
			return
		}
		update_query := "insert into films_to_actors(film_name, actor_name) values ($1, $2)"
		for i := 0; i < len(actors); i++ {
			_, err = db.Exec(update_query, name, actors[i])
			if err != nil {
				writeToResponse(w, Message{400, "Cannot update actors"}, 400, logger)
				logger.Printf("Failed to update actors: %v\n", err)
				return
			}
		}
	}
	if new_name != "" {
		update_query := "DELETE from films_to_actors WHERE film_name = $1"
		_, err := db.Exec(update_query, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update name"}, 400, logger)
			logger.Printf("Failed to update name: %v\n", err)
			return
		}
		update_query = "UPDATE films SET name = $1 WHERE name = $2"
		_, err = db.Exec(update_query, new_name, name)
		if err != nil {
			writeToResponse(w, Message{400, "Cannot update name"}, 400, logger)
			logger.Printf("Failed to update name: %v\n", err)
			return
		}
		update_query = "insert into films_to_actors(film_name, actor_name) values ($1, $2)"
		for i := 0; i < len(actors); i++ {
			_, err = db.Exec(update_query, new_name, actors[i])
			if err != nil {
				writeToResponse(w, Message{400, "Cannot update actors"}, 400, logger)
				logger.Printf("Failed to update actors: %v\n", err)
				return
			}
		}
	}
	writeToResponse(w, Message{200, "User updated successfully"}, 200, logger)
}

func getFilm(sort_by string, db *sql.DB, logger *log.Logger, w http.ResponseWriter) {
	resp := films_resp{Films: make([]film, 0)}
	switch sort_by {
	case "title":
		query := "SELECT * FROM films ORDER BY name DESC"
		rows, err := db.Query(query)
		if err != nil {
			writeToResponse(w, Message{500, "Cannot get films"}, 500, logger)
			logger.Printf("Failed to get films: %v\n", err)
		}
		for rows.Next() {
			var name string
			var description string
			var releaseDate string
			var rate float32
			var id int
			err := rows.Scan(&id, &name, &description, &releaseDate, &rate)
			if err != nil {
				panic(err)
			}
			resp.Films = append(resp.Films, film{Name: name, Description: description, ProductionDate: releaseDate, Rate: rate})
		}
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
			logger.Printf("Error marshaling JSON: %v\n", err)
			return
		}
		_, err = w.Write(jsonData)
		if err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			logger.Printf("Error writing response: %v\n", err)
			return
		}
	case "release_date":
		query := "SELECT * FROM films ORDER BY production_date DESC"
		rows, err := db.Query(query)
		if err != nil {
			writeToResponse(w, Message{500, "Cannot get films"}, 500, logger)
			logger.Printf("Failed to get films: %v\n", err)
		}
		for rows.Next() {
			var name string
			var description string
			var releaseDate string
			var rate float32
			var id int
			err := rows.Scan(&id, &name, &description, &releaseDate, &rate)
			if err != nil {
				panic(err)
			}
			resp.Films = append(resp.Films, film{Name: name, Description: description, ProductionDate: releaseDate, Rate: rate})
		}
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
			logger.Printf("Error marshaling JSON: %v\n", err)
			return
		}
		_, err = w.Write(jsonData)
		if err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			logger.Printf("Error writing response: %v\n", err)
			return
		}
	default:
		query := "SELECT * FROM films ORDER BY rate DESC"
		rows, err := db.Query(query)
		if err != nil {
			writeToResponse(w, Message{500, "Cannot get films"}, 500, logger)
			logger.Printf("Failed to get films: %v\n", err)
		}
		for rows.Next() {
			var name string
			var description string
			var releaseDate string
			var rate float32
			var id int
			err := rows.Scan(&id, &name, &description, &releaseDate, &rate)
			if err != nil {
				panic(err)
			}
			resp.Films = append(resp.Films, film{Name: name, Description: description, ProductionDate: releaseDate, Rate: rate})
		}
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
			logger.Printf("Error marshaling JSON: %v\n", err)
			return
		}
		_, err = w.Write(jsonData)
		if err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			logger.Printf("Error writing response: %v\n", err)
			return
		}
	}
}

func getActors(db *sql.DB, logger *log.Logger, w http.ResponseWriter) {
	actors_query := "SELECT * from actors"
	films_query := "SELECT film_name from films_to_actors where actor_name=$1"
	resp := actor_resp{Actors: make([]actor_films, 0)}
	rows, err := db.Query(actors_query)
	if err != nil {
		writeToResponse(w, Message{500, "Cannot get actors"}, 500, logger)
		logger.Printf("Failed to get actors: %v\n", err)
		return
	}
	for rows.Next() {
		var id int
		var name string
		var gender string
		var birth_date string
		var temp actor_films
		err := rows.Scan(&id, &name, &gender, &birth_date)
		if err != nil {
			writeToResponse(w, Message{500, "Cannot get actors"}, 500, logger)
			logger.Printf("Failed to get actors: %v\n", err)
			return
		}
		temp = actor_films{name, gender, birth_date, make([]string, 0)}
		rows1, err1 := db.Query(films_query, name)
		if err1 != nil {
			writeToResponse(w, Message{500, "Cannot get actors"}, 500, logger)
			logger.Printf("Failed to get actors: %v\n", err)
			return
		}
		for rows1.Next() {
			var film_name string
			err := rows1.Scan(&film_name)
			if err != nil {
				writeToResponse(w, Message{500, "Cannot get actors"}, 500, logger)
				logger.Printf("Failed to get actors: %v\n", err)
				return
			}
			temp.Films = append(temp.Films, film_name)
		}
		resp.Actors = append(resp.Actors, temp)
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
		logger.Printf("Error marshaling JSON: %v\n", err)
		return
	}
	_, err = w.Write(jsonData)
	if err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		logger.Printf("Error writing response: %v\n", err)
		return
	}
}
