package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB is the global database instance
var DB *gorm.DB

// GetEnvDefault gets an environment variable or returns a default value
func GetEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDatabasePassword() (string, error) {
	explicit := os.Getenv("DB_PASSWORD")
	// Treat the literal "vault" as a signal to fetch dynamically.
	if explicit != "" && !strings.EqualFold(explicit, "vault") {
		return explicit, nil
	}

	password, err := fetchDBPasswordFromVault()
	if err != nil {
		if explicit != "" {
			// Explicit request to use Vault but fetch failed: propagate error.
			return "", err
		}
		return "", fmt.Errorf("fetch DB password from Vault: %w", err)
	}

	log.Println("🔐 Retrieved database password from Vault")
	_ = os.Setenv("DB_PASSWORD", password)
	return password, nil
}

func fetchDBPasswordFromVault() (string, error) {
	if strings.EqualFold(os.Getenv("VAULT_ENABLED"), "false") {
		return "", errors.New("vault integration disabled")
	}

	addr := strings.TrimRight(os.Getenv("VAULT_ADDR"), "/")
	if addr == "" {
		return "", errors.New("VAULT_ADDR not set")
	}

	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if token == "" {
		tokenFile := os.Getenv("VAULT_TOKEN_FILE")
		if tokenFile == "" {
			return "", errors.New("missing VAULT_TOKEN or VAULT_TOKEN_FILE")
		}
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read vault token: %w", err)
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		return "", errors.New("vault token empty")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	staticRole := os.Getenv("VAULT_DB_STATIC_ROLE")
	if staticRole == "" {
		staticRole = "backend-static"
	}

	if password, err := readVaultStaticCreds(client, addr, token, staticRole); err == nil && password != "" {
		return password, nil
	} else if err != nil {
		log.Printf("⚠️  Unable to read static creds from Vault: %v", err)
	}

	password, err := readVaultKVSecret(client, addr, token)
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("db password not found in Vault secret")
	}
	return password, nil
}

func readVaultStaticCreds(client *http.Client, addr, token, role string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/database/static-creds/%s", addr, role), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("vault static-creds %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Data struct {
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode static creds: %w", err)
	}
	return payload.Data.Password, nil
}

func readVaultKVSecret(client *http.Client, addr, token string) (string, error) {
	secretPath := os.Getenv("VAULT_SECRETS_PATH")
	if secretPath == "" {
		secretPath = "secret/backend"
	}

	dataPath := secretPath
	if !strings.Contains(dataPath, "/data/") {
		if parts := strings.SplitN(dataPath, "/", 2); len(parts) == 2 {
			dataPath = fmt.Sprintf("%s/data/%s", parts[0], parts[1])
		} else {
			dataPath = fmt.Sprintf("secret/data/%s", dataPath)
		}
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/%s", addr, dataPath), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("vault kv %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode kv secret: %w", err)
	}

	for _, key := range []string{"DB_PASSWORD", "db_password"} {
		if raw, ok := payload.Data.Data[key]; ok {
			switch v := raw.(type) {
			case string:
				return v, nil
			}
		}
	}
	return "", nil
}

// InitDatabase initializes the database connection
func InitDatabase() error {
	// Use environment variables for database connection (with Vault support)
	host := GetEnvDefault("DB_HOST", "localhost")
	port := GetEnvDefault("DB_PORT", "5432")
	user := GetEnvDefault("DB_USER", "prysm")
	password, err := getDatabasePassword()
	if err != nil {
		return fmt.Errorf("resolve database password: %w", err)
	}
	dbname := GetEnvDefault("DB_NAME", "prysm")

	// Security: Use SSL mode based on environment, default to require for production
	sslMode := GetEnvDefault("DB_SSLMODE", "require")
	if os.Getenv("DB_SSLMODE") == "" && (os.Getenv("ENVIRONMENT") == "development" || os.Getenv("ENVIRONMENT") == "dev") {
		sslMode = "disable"
		log.Println("⚠️  Database SSL disabled for development environment")
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		host, user, password, dbname, port, sslMode)

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		// Check if we're in standalone DNS mode
		if os.Getenv("DISABLE_HTTP_SERVER") == "true" && os.Getenv("DNS_SERVER") == "true" {
			log.Printf("⚠️  Database connection failed in DNS-only mode: %v", err)
			log.Println("✅ Running in standalone DNS mode without database")
			DB = nil
			return nil
		}
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Println("✅ Database connected successfully")
	return nil
}

// RunMigrations runs all database migrations
func RunMigrations(models ...interface{}) error {
	if DB == nil {
		log.Println("⚠️  Skipping migrations: no database connection")
		return nil
	}

	log.Println("Running database migrations...")

	// Check if we should drop tables (for development only)
	dropTables := GetEnvDefault("DROP_TABLES_ON_STARTUP", "false")

	if dropTables == "true" {
		log.Println("⚠️  Dropping existing tables (development mode)")
		DB.Exec("DROP TABLE IF EXISTS dashboards CASCADE")
		DB.Exec("DROP TABLE IF EXISTS queries CASCADE")
		DB.Exec("DROP TABLE IF EXISTS data_sources CASCADE")
		DB.Exec("DROP TABLE IF EXISTS organization_members CASCADE")
		DB.Exec("DROP TABLE IF EXISTS invitations CASCADE")
		DB.Exec("DROP TABLE IF EXISTS usage_records CASCADE")
		DB.Exec("DROP TABLE IF EXISTS payment_methods CASCADE")
		DB.Exec("DROP TABLE IF EXISTS invoices CASCADE")
		DB.Exec("DROP TABLE IF EXISTS audit_logs CASCADE")
		DB.Exec("DROP TABLE IF EXISTS permissions CASCADE")
		DB.Exec("DROP TABLE IF EXISTS commands CASCADE")
		DB.Exec("DROP TABLE IF EXISTS sessions CASCADE")
		DB.Exec("DROP TABLE IF EXISTS clusters CASCADE")
		DB.Exec("DROP TABLE IF EXISTS subscriptions CASCADE")
		DB.Exec("DROP TABLE IF EXISTS organizations CASCADE")
		DB.Exec("DROP TABLE IF EXISTS plans CASCADE")
		DB.Exec("DROP TABLE IF EXISTS users CASCADE")
	}

	// Run auto-migration
	if err := DB.AutoMigrate(models...); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Println("✅ Database migrations completed")
	return nil
}
