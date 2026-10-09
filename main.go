package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	db       *sql.DB
	config   Config
	settings Settings
}

type Config struct {
	Port              string
	DatabasePath      string
	SMTPHost          string
	SMTPPort          string
	SMTPUser          string
	SMTPPassword      string
	SMTPFrom          string
	JWTSecret         string
	AllowPublicSignup bool
}

type Settings struct {
	AppName        string
	AppDescription string
	AppIcon        string
	PublicSignup   bool
}

type User struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	PasswordHash    string    `json:"-"`
	TwoFAEnabled    bool      `json:"two_fa_enabled"`
	TwoFASecret     string    `json:"-"`
	IsAdmin         bool      `json:"is_admin"`
	CreatedAt       time.Time `json:"created_at"`
	LastLoginAt     *time.Time `json:"last_login_at"`
}

type TOTPExport struct {
	Secret   string `json:"secret"`
	Email    string `json:"email"`
	Issuer   string `json:"issuer"`
	Verified bool   `json:"verified"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

type AuthResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	godotenv.Load()

	config := Config{
		Port:              getEnv("PORT", "8080"),
		DatabasePath:      getEnv("DATABASE_PATH", "/data/auth.db"),
		SMTPHost:          getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:          getEnv("SMTP_PORT", "587"),
		SMTPUser:          getEnv("SMTP_USER", ""),
		SMTPPassword:      getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:          getEnv("SMTP_FROM", "noreply@example.com"),
		JWTSecret:         getEnv("JWT_SECRET", "your-secret-key-change-in-production"),
		AllowPublicSignup: getEnv("ALLOW_PUBLIC_SIGNUP", "true") == "true",
	}

	app, err := NewApp(config)
	if err != nil {
		log.Fatalf("Failed to initialise app: %v", err)
	}
	defer app.db.Close()

	router := http.NewServeMux()

	// API routes
	router.HandleFunc("POST /api/auth/register", app.handleRegister)
	router.HandleFunc("POST /api/auth/login", app.handleLogin)
	router.HandleFunc("POST /api/auth/verify-2fa", app.handleVerify2FA)
	router.HandleFunc("POST /api/auth/enable-2fa", app.authenticate(app.handleEnable2FA))
	router.HandleFunc("POST /api/auth/disable-2fa", app.authenticate(app.handleDisable2FA))
	router.HandleFunc("POST /api/auth/export-2fa", app.authenticate(app.handleExport2FA))
	router.HandleFunc("POST /api/auth/import-2fa", app.authenticate(app.handleImport2FA))
	router.HandleFunc("GET /api/user", app.authenticate(app.handleGetUser))
	router.HandleFunc("POST /api/user/password", app.authenticate(app.handleChangePassword))
	router.HandleFunc("POST /api/settings", app.authenticateAdmin(app.handleUpdateSettings))
	router.HandleFunc("GET /api/settings", app.handleGetSettings)
	router.HandleFunc("GET /api/users", app.authenticateAdmin(app.handleListUsers))
	router.HandleFunc("DELETE /api/users/{id}", app.authenticateAdmin(app.handleDeleteUser))

	// Static files
	router.Handle("/", http.FileServer(http.Dir("./static")))

	log.Printf("Auth app starting on :%s\n", config.Port)
	if err := http.ListenAndServe(":"+config.Port, router); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func NewApp(cfg Config) (*App, error) {
	os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0755)

	db, err := sql.Open("sqlite3", cfg.DatabasePath)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	app := &App{
		db:     db,
		config: cfg,
		settings: Settings{
			AppName:        getEnv("APP_NAME", "Auth App"),
			AppDescription: getEnv("APP_DESCRIPTION", "Secure authentication with 2FA"),
			AppIcon:        getEnv("APP_ICON", "🔐"),
			PublicSignup:   cfg.AllowPublicSignup,
		},
	}

	if err := app.initDB(); err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) initDB() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		two_fa_enabled BOOLEAN DEFAULT 0,
		two_fa_secret TEXT,
		is_admin BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_email ON users(email);
	`

	if _, err := a.db.Exec(schema); err != nil {
		return err
	}

	// Load or create default settings
	var count int
	a.db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count)
	if count == 0 {
		_, err := a.db.Exec(`
			INSERT INTO settings (key, value) VALUES
			('app_name', ?),
			('app_description', ?),
			('app_icon', ?),
			('public_signup', ?)
		`, a.settings.AppName, a.settings.AppDescription, a.settings.AppIcon, "true")
		return err
	}

	return nil
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !a.settings.PublicSignup {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Public registration disabled"}), http.StatusForbidden)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid request"}), http.StatusBadRequest)
		return
	}

	if err := validateEmail(req.Email); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: err.Error()}), http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Failed to process password"}), http.StatusInternalServerError)
		return
	}

	userID := uuid.New().String()
	isAdmin := false

	var userCount int
	a.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if userCount == 0 {
		isAdmin = true
	}

	_, err = a.db.Exec(`
		INSERT INTO users (id, email, password_hash, is_admin)
		VALUES (?, ?, ?, ?)
	`, userID, req.Email, string(hash), isAdmin)

	if err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Email already registered"}), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{Message: "Registration successful"})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid request"}), http.StatusBadRequest)
		return
	}

	user, err := a.getUserByEmail(req.Email)
	if err != nil || user == nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid credentials"}), http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid credentials"}), http.StatusUnauthorized)
		return
	}

	if user.TwoFAEnabled && req.TOTPCode == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"message": "2FA code required"})
		return
	}

	if user.TwoFAEnabled {
		if !a.verifyTOTP(user.TwoFASecret, req.TOTPCode) {
			http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid 2FA code"}), http.StatusUnauthorized)
			return
		}
	}

	token := a.generateToken(user.ID)
	a.db.Exec("UPDATE users SET last_login_at = ? WHERE id = ?", time.Now(), user.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{Token: token, Message: "Login successful"})
}

func (a *App) handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid request"}), http.StatusBadRequest)
		return
	}

	user, err := a.getUserByEmail(req.Email)
	if err != nil || user == nil || !user.TwoFAEnabled {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid request"}), http.StatusBadRequest)
		return
	}

	if !a.verifyTOTP(user.TwoFASecret, req.TOTPCode) {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid code"}), http.StatusUnauthorized)
		return
	}

	token := a.generateToken(user.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{Token: token})
}

func (a *App) handleEnable2FA(w http.ResponseWriter, r *http.Request, user *User) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.settings.AppName,
		AccountName: user.Email,
	})
	if err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Failed to generate 2FA"}), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret": key.Secret(),
		"qr":     fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", a.settings.AppName, user.Email, key.Secret(), a.settings.AppName),
	})
}

func (a *App) handleDisable2FA(w http.ResponseWriter, r *http.Request, user *User) {
	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid request"}), http.StatusBadRequest)
		return
	}

	if !a.verifyTOTP(user.TwoFASecret, req.TOTPCode) {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid code"}), http.StatusUnauthorized)
		return
	}

	a.db.Exec("UPDATE users SET two_fa_enabled = 0, two_fa_secret = NULL WHERE id = ?", user.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA disabled"})
}

func (a *App) handleExport2FA(w http.ResponseWriter, r *http.Request, user *User) {
	if !user.TwoFAEnabled {
		http.Error(w, json.Marshal(ErrorResponse{Error: "2FA not enabled"}), http.StatusBadRequest)
		return
	}

	export := TOTPExport{
		Secret:   user.TwoFASecret,
		Email:    user.Email,
		Issuer:   a.settings.AppName,
		Verified: true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=2fa-export-%s.json", time.Now().Format("20060102")))
	json.NewEncoder(w).Encode(export)
}

func (a *App) handleImport2FA(w http.ResponseWriter, r *http.Request, user *User) {
	var imports []TOTPExport
	if err := json.NewDecoder(r.Body).Decode(&imports); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid JSON"}), http.StatusBadRequest)
		return
	}

	if len(imports) == 0 {
		http.Error(w, json.Marshal(ErrorResponse{Error: "No imports provided"}), http.StatusBadRequest)
		return
	}

	// Use first import
	imp := imports[0]
	a.db.Exec("UPDATE users SET two_fa_enabled = 1, two_fa_secret = ? WHERE id = ?", imp.Secret, user.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA imported"})
}

func (a *App) handleGetUser(w http.ResponseWriter, r *http.Request, user *User) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request, user *User) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid request"}), http.StatusBadRequest)
		return
	}

	dbUser, _ := a.getUserByID(user.ID)
	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(req.OldPassword)); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Current password incorrect"}), http.StatusUnauthorized)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	a.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hash), user.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password updated"})
}

func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request, admin *User) {
	var settings Settings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid request"}), http.StatusBadRequest)
		return
	}

	a.db.Exec("UPDATE settings SET value = ? WHERE key = 'app_name'", settings.AppName)
	a.db.Exec("UPDATE settings SET value = ? WHERE key = 'app_description'", settings.AppDescription)
	a.db.Exec("UPDATE settings SET value = ? WHERE key = 'app_icon'", settings.AppIcon)
	a.db.Exec("UPDATE settings SET value = ? WHERE key = 'public_signup'", settings.PublicSignup)

	a.settings = settings

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Settings updated"})
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.settings)
}

func (a *App) handleListUsers(w http.ResponseWriter, r *http.Request, admin *User) {
	rows, err := a.db.Query("SELECT id, email, two_fa_enabled, is_admin, created_at, last_login_at FROM users")
	if err != nil {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Database error"}), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Email, &u.TwoFAEnabled, &u.IsAdmin, &u.CreatedAt, &u.LastLoginAt)
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (a *App) handleDeleteUser(w http.ResponseWriter, r *http.Request, admin *User) {
	id := r.PathValue("id")
	if id == admin.ID {
		http.Error(w, json.Marshal(ErrorResponse{Error: "Cannot delete self"}), http.StatusBadRequest)
		return
	}

	a.db.Exec("DELETE FROM users WHERE id = ?", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted"})
}

func (a *App) authenticate(next func(http.ResponseWriter, *http.Request, *User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, json.Marshal(ErrorResponse{Error: "Unauthorised"}), http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid token"}), http.StatusUnauthorized)
			return
		}

		userID, err := a.verifyToken(parts[1])
		if err != nil {
			http.Error(w, json.Marshal(ErrorResponse{Error: "Invalid token"}), http.StatusUnauthorized)
			return
		}

		user, err := a.getUserByID(userID)
		if err != nil || user == nil {
			http.Error(w, json.Marshal(ErrorResponse{Error: "User not found"}), http.StatusUnauthorized)
			return
		}

		next(w, r, user)
	}
}

func (a *App) authenticateAdmin(next func(http.ResponseWriter, *http.Request, *User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHandler := a.authenticate(func(w http.ResponseWriter, r *http.Request, user *User) {
			if !user.IsAdmin {
				http.Error(w, json.Marshal(ErrorResponse{Error: "Admin access required"}), http.StatusForbidden)
				return
			}
			next(w, r, user)
		})
		authHandler(w, r)
	}
}

func (a *App) getUserByEmail(email string) (*User, error) {
	var user User
	err := a.db.QueryRow(`
		SELECT id, email, password_hash, two_fa_enabled, two_fa_secret, is_admin, created_at, last_login_at
		FROM users WHERE email = ?
	`, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.TwoFAEnabled, &user.TwoFASecret, &user.IsAdmin, &user.CreatedAt, &user.LastLoginAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (a *App) getUserByID(id string) (*User, error) {
	var user User
	err := a.db.QueryRow(`
		SELECT id, email, password_hash, two_fa_enabled, two_fa_secret, is_admin, created_at, last_login_at
		FROM users WHERE id = ?
	`, id).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.TwoFAEnabled, &user.TwoFASecret, &user.IsAdmin, &user.CreatedAt, &user.LastLoginAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &user, err
}

func (a *App) verifyTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

func (a *App) generateToken(userID string) string {
	h := sha256.New()
	h.Write([]byte(userID + a.config.JWTSecret + time.Now().String()))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (a *App) verifyToken(token string) (string, error) {
	// Simplified token verification; in production, use proper JWT
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	// For now, store tokens in memory or database for validation
	return "", fmt.Errorf("token verification not implemented")
}

func validateEmail(email string) error {
	if !strings.Contains(email, "@") {
		return fmt.Errorf("invalid email address")
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
