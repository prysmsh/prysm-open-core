package auth

import (
	"log"
	"os"
	"sync"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/microsoftonline"
)

var (
	oauthProvidersMu sync.RWMutex
	oauthProviders   = make(map[string]bool)
)

// InitOAuth initializes OAuth providers from environment variables
func InitOAuth() {
	resetOAuthProviders()

	var providers []goth.Provider

	// GitHub OAuth
	if os.Getenv("GITHUB_CLIENT_ID") != "" && os.Getenv("GITHUB_CLIENT_SECRET") != "" {
		callbackURL := os.Getenv("GITHUB_CALLBACK_URL")
		if callbackURL == "" {
			callbackURL = "http://localhost:8080/api/v1/auth/github/callback"
		}

		providers = append(providers, github.New(
			os.Getenv("GITHUB_CLIENT_ID"),
			os.Getenv("GITHUB_CLIENT_SECRET"),
			callbackURL,
			"user:email",
		))
		markOAuthProviderConfigured("github")
		log.Println("✅ GitHub OAuth configured")
	}

	// Google OAuth
	if os.Getenv("GOOGLE_CLIENT_ID") != "" && os.Getenv("GOOGLE_CLIENT_SECRET") != "" {
		callbackURL := os.Getenv("GOOGLE_CALLBACK_URL")
		if callbackURL == "" {
			callbackURL = "http://localhost:8080/api/v1/auth/google/callback"
		}

		providers = append(providers, google.New(
			os.Getenv("GOOGLE_CLIENT_ID"),
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			callbackURL,
			"email", "profile",
		))
		markOAuthProviderConfigured("google")
		log.Println("✅ Google OAuth configured")
	}

	// Microsoft OAuth
	if os.Getenv("MICROSOFT_CLIENT_ID") != "" && os.Getenv("MICROSOFT_CLIENT_SECRET") != "" {
		callbackURL := os.Getenv("MICROSOFT_CALLBACK_URL")
		if callbackURL == "" {
			callbackURL = "http://localhost:8080/api/v1/auth/microsoft/callback"
		}

		providers = append(providers, microsoftonline.New(
			os.Getenv("MICROSOFT_CLIENT_ID"),
			os.Getenv("MICROSOFT_CLIENT_SECRET"),
			callbackURL,
			"openid", "profile", "email",
		))
		markOAuthProviderConfigured("microsoft")
		log.Println("✅ Microsoft OAuth configured")
	}

	if len(providers) > 0 {
		goth.UseProviders(providers...)
		log.Printf("✅ OAuth initialized with %d providers", len(providers))
	} else {
		log.Println("⚠️  No OAuth providers configured")
	}
}

func resetOAuthProviders() {
	oauthProvidersMu.Lock()
	defer oauthProvidersMu.Unlock()
	oauthProviders = make(map[string]bool)
}

func markOAuthProviderConfigured(provider string) {
	oauthProvidersMu.Lock()
	defer oauthProvidersMu.Unlock()
	oauthProviders[provider] = true
}

func IsOAuthProviderConfigured(provider string) bool {
	oauthProvidersMu.RLock()
	defer oauthProvidersMu.RUnlock()
	return oauthProviders[provider]
}

