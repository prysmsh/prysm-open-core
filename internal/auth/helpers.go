package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// GenerateToken64 generates a random 64-character token
func GenerateToken64() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetTrialEndDate returns a pointer to the trial end date (14 days from now)
func GetTrialEndDate() *time.Time {
	trialEnd := time.Now().AddDate(0, 0, 14) // 14 days trial
	return &trialEnd
}

// ValidateTOTP validates a TOTP code against a secret
func ValidateTOTP(secret, token string) bool {
	return totp.Validate(token, secret)
}

// HashBackupCode hashes a backup code using SHA256
func HashBackupCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// ValidateBackupCode validates a backup code for a user
func ValidateBackupCode(user *models.User, code string) bool {
	if code == "" {
		return false
	}

	if database.DB == nil {
		return false
	}

	candidateHash := HashBackupCode(code)
	for i, backupHash := range user.MFABackupCodes {
		if strings.EqualFold(backupHash, candidateHash) {
			// Remove used backup code
			user.MFABackupCodes = append(user.MFABackupCodes[:i], user.MFABackupCodes[i+1:]...)
			database.DB.Save(user)
			return true
		}
	}
	return false
}

// GenerateSessionID generates a random session ID
func GenerateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetEnvInt retrieves an integer environment variable with a default value
func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// RevokeAllDatabaseSessionsForUser revokes all active database sessions for a user
func RevokeAllDatabaseSessionsForUser(userID uint, orgID uint) error {
	if database.DB == nil || userID == 0 {
		return nil
	}

	var sessions []models.Session
	query := database.DB.Where("status = ?", "active").Where("user_id = ?", userID)
	if orgID != 0 {
		query = query.Where("organization_id = ?", orgID)
	}
	if err := query.Find(&sessions).Error; err != nil {
		return err
	}

	for _, session := range sessions {
		// Update session status to revoked
		session.Status = "revoked"
		if err := database.DB.Save(&session).Error; err != nil {
			log.Printf("Failed to revoke session %s for user %d: %v", session.SessionID, userID, err)
		}
	}

	return nil
}

// GenerateBackupCodes generates 10 backup codes for MFA
func GenerateBackupCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := range codes {
		bytes := make([]byte, 4)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		codes[i] = strings.ToUpper(hex.EncodeToString(bytes))
	}
	return codes, nil
}

// HashBackupCodes hashes an array of backup codes
func HashBackupCodes(codes []string) []string {
	hashed := make([]string, len(codes))
	for i, code := range codes {
		hashed[i] = HashBackupCode(code)
	}
	return hashed
}

// GenerateMFASecret generates a TOTP secret for a user
func GenerateMFASecret(userEmail string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Prysm",
		AccountName: userEmail,
		SecretSize:  32,
	})
	return key, err
}

// RevokeAllUserTokens revokes all tokens for a user (stub for vault integration)
func RevokeAllUserTokens(userID uint) {
	// TODO: Implement vault token revocation when vault package is extracted
	log.Printf("TODO: Revoke all tokens for user %d", userID)
}

// Note: The following functions depend on vault/session management that will need to be extracted later:
// - storeUserTokenInVault
// - removeUserTokenFromVault
// These will be handled when we extract session management to a separate package.

