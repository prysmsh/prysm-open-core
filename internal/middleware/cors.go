package middleware

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
)

// SecureCORSConfig returns a secure CORS configuration
func SecureCORSConfig() cors.Config {
	config := cors.DefaultConfig()

	// Get allowed origins from environment
	allowedOriginsStr := os.Getenv("CORS_ORIGINS")
	var allowedOrigins []string

	if allowedOriginsStr != "" {
		origins := strings.Split(allowedOriginsStr, ",")
		for _, origin := range origins {
			origin = strings.TrimSpace(origin)
			if origin == "" {
				continue
			}
			if err := validateCORSOrigin(origin); err != nil {
				log.Printf("Warning: Invalid CORS origin '%s': %v", origin, err)
				continue
			}
			allowedOrigins = append(allowedOrigins, origin)
		}
	}

	// Add development origins if in dev environment
	env := strings.ToLower(os.Getenv("ENVIRONMENT"))
	if env == "development" || env == "dev" {
		devOrigins := []string{
			"http://localhost:3000",
			"http://localhost:8080",
			"http://localhost:8444",
			"https://localhost:8444",
		}
		for _, origin := range devOrigins {
			if !containsString(allowedOrigins, origin) {
				allowedOrigins = append(allowedOrigins, origin)
			}
		}
		log.Printf("Development mode: Added default localhost origins to CORS")
	}

	if len(allowedOrigins) == 0 {
		log.Println("⚠️  No CORS origins configured, CORS will be restrictive")
		allowedOrigins = []string{"https://example.com"}
	}

	if containsString(allowedOrigins, "*") && (env == "production" || env == "prod") {
		log.Fatal("CRITICAL: Wildcard CORS origin (*) is not allowed in production")
	}

	config.AllowOrigins = allowedOrigins
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{
		"Origin", "Content-Type", "Accept", "Authorization",
		"X-CSRF-Token", "X-Requested-With",
	}
	config.ExposeHeaders = []string{
		"Content-Length", "Content-Type",
		"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
	}
	config.AllowCredentials = true
	config.MaxAge = 12 * time.Hour

	log.Printf("✅ CORS configured with %d allowed origins", len(allowedOrigins))
	return config
}

func validateCORSOrigin(origin string) error {
	if origin == "*" {
		return nil
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return err
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid scheme: %s (must be http or https)", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("missing host in origin")
	}

	return nil
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

