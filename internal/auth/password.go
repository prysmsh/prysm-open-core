package auth

import (
	"fmt"
	"time"
	
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	
	"prysm-backend/internal/models"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

// CheckPassword verifies a password against a hash
func CheckPassword(password, hash string) bool {
	start := time.Now()
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	duration := time.Since(start)
	if duration > 1*time.Second {
		// Log if bcrypt takes more than 1 second
		fmt.Printf("CheckPassword: bcrypt took %v\n", duration)
	}
	if err != nil {
		return false
	}
	return true
}

// IsAccountLocked checks if a user account is locked
func IsAccountLocked(user *models.User) bool {
	return user.LockedUntil != nil && time.Now().Before(*user.LockedUntil)
}

// RecordFailedLogin records a failed login attempt
func RecordFailedLogin(db *gorm.DB, user *models.User) error {
	user.FailedLoginAttempts++
	user.LastFailedLogin = &[]time.Time{time.Now()}[0]

	// Lock account after 5 failed attempts
	if user.FailedLoginAttempts >= 5 {
		lockDuration := 30 * time.Minute
		lockUntil := time.Now().Add(lockDuration)
		user.LockedUntil = &lockUntil
	}

	return db.Save(user).Error
}

// RecordSuccessfulLogin resets failed login attempts
func RecordSuccessfulLogin(db *gorm.DB, user *models.User) error {
	user.FailedLoginAttempts = 0
	user.LastFailedLogin = nil
	user.LockedUntil = nil
	return db.Save(user).Error
}

// ValidateOrganizationMembership checks if a user belongs to an organization
func ValidateOrganizationMembership(db *gorm.DB, userID, organizationID uint) error {
	var count int64
	db.Model(&models.OrganizationMember{}).
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Count(&count)

	if count == 0 {
		return fmt.Errorf("user is not a member of this organization")
	}

	return nil
}

