package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	
	"prysm-backend/internal/models"
)

const bcryptCost = 14

var jwtSecret []byte

// Claims represents JWT claims
type Claims struct {
	UserID         uint   `json:"user_id"`
	Email          string `json:"email"`
	OrganizationID uint   `json:"organization_id"`
	Role           string `json:"role"`
	jwt.RegisteredClaims
}

// InitJWT initializes JWT secret from environment
func InitJWT() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	jwtSecret = []byte(secret)
	log.Println("✅ JWT initialized")
}

// GenerateToken generates a JWT token for a user
func GenerateToken(user models.User, orgID uint) (string, time.Time, string, error) {
	return GenerateTokenWithTTL(user, orgID, 24*time.Hour)
}

// GenerateTokenWithTTL generates a JWT token with custom TTL
func GenerateTokenWithTTL(user models.User, orgID uint, ttl time.Duration) (string, time.Time, string, error) {
	expiry := time.Now().Add(ttl)
	return buildToken(user, orgID, expiry)
}

func buildToken(user models.User, orgID uint, expiry time.Time) (string, time.Time, string, error) {
	claims := &Claims{
		UserID:         user.ID,
		Email:          user.Email,
		OrganizationID: orgID,
		Role:           user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("failed to sign token: %w", err)
	}

	csrfToken, err := generateCSRFToken()
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	return tokenString, expiry, csrfToken, nil
}

// ParseToken parses and validates a JWT token
func ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// IsTokenBlacklisted checks if a token is blacklisted
func IsTokenBlacklisted(db *gorm.DB, tokenString string) bool {
	if db == nil {
		return false
	}

	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	var count int64
	db.Model(&models.TokenBlacklist{}).Where("token_hash = ?", tokenHash).Count(&count)
	return count > 0
}

// BlacklistToken adds a token to the blacklist
func BlacklistToken(db *gorm.DB, tokenString string, expiry time.Time) {
	if db == nil {
		return
	}

	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	blacklist := models.TokenBlacklist{
		TokenHash: tokenHash,
		ExpiresAt: expiry,
	}

	db.Create(&blacklist)
}

// CleanupTokenBlacklist removes expired tokens from blacklist
func CleanupTokenBlacklist(db *gorm.DB) {
	if db == nil {
		return
	}
	
	result := db.Where("expires_at < ?", time.Now()).Delete(&models.TokenBlacklist{})
	if result.Error == nil && result.RowsAffected > 0 {
		log.Printf("Cleaned up %d expired tokens from blacklist", result.RowsAffected)
	}
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateRefreshToken generates a refresh token for a user
func GenerateRefreshToken(userID, organizationID uint) (string, time.Time, error) {
	expiry := time.Now().Add(7 * 24 * time.Hour) // 7 days

	claims := jwt.MapClaims{
		"user_id":         userID,
		"organization_id": organizationID,
		"type":            "refresh",
		"iat":             time.Now().Unix(),
		"exp":             expiry.Unix(),
		"iss":             "prysm",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	// TODO: Store refresh token in vault if vault is enabled
	// This would call storeUserTokenInVault("refresh", tokenString, userID, expiry)

	return tokenString, expiry, nil
}

