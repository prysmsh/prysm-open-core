package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"prysm-backend/internal/database"
	apperrors "prysm-backend/internal/errors"
	"prysm-backend/internal/middleware"
	"prysm-backend/internal/models"
	"prysm-backend/pkg/utils"
)

// HandleLogin handles user login
func HandleLogin(c *gin.Context) {
	clientIP := utils.GetClientIP(c)
	start := time.Now()
	log.Printf("LOGIN attempt from %s origin=%s csrf_header=%s", clientIP, c.GetHeader("Origin"), c.GetHeader("X-CSRF-Token"))

	// Get validated values from context
	log.Printf("LOGIN: Getting validated values from context")
	email := utils.GetValidatedString(c, "validated_email")
	password := utils.GetValidatedString(c, "validated_password")
	log.Printf("LOGIN: Got email=%s", email)

	if email == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and password are required"})
		return
	}

	// Parse additional fields from request body
	var req struct {
		TOTPCode   string `json:"totp_code,omitempty"`
		BackupCode string `json:"backup_code,omitempty"`
	}

	if raw, exists := c.Get("validated_raw_body"); exists {
		if bodyBytes, ok := raw.([]byte); ok && len(bodyBytes) > 0 {
			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
				return
			}
		}
	}

	// Validate TOTP and backup codes if provided
	if req.TOTPCode != "" {
		// Basic validation - TODO: Use validation package when extracted
		if len(req.TOTPCode) != 6 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "Validation failed",
				"validation_errors": []gin.H{{"field": "totp_code", "message": "TOTP code must be 6 digits"}},
			})
			return
		}
	}

	if req.BackupCode != "" {
		if len(req.BackupCode) != 8 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "Validation failed",
				"validation_errors": []gin.H{{"field": "backup_code", "message": "Backup code must be 8 alphanumeric characters"}},
			})
			return
		}
	}

	// Find user
	log.Printf("LOGIN: Looking up user in database")
	var user models.User
	if err := database.DB.Where("email = ? AND active = ?", email, true).First(&user).Error; err != nil {
		log.Printf("LOGIN: Database query error: %v", err)
		if err == gorm.ErrRecordNotFound {
			respondInvalidCredentials(c)
			return
		}
		utils.SendErrorResponse(c, http.StatusInternalServerError, &apperrors.AppError{
			Code:    "DATABASE_ERROR",
			Message: "Database error occurred",
			Details: "Failed to query user",
			Err:     err,
		})
		return
	}
	log.Printf("LOGIN: Found user %s", user.Email)

	// Check if account is locked
	log.Printf("LOGIN: Checking if account is locked")
	if IsAccountLocked(&user) {
		lockRemaining := user.LockedUntil.Sub(time.Now())
		log.Printf("LOGIN: Account is locked until %s", user.LockedUntil)
		utils.SendErrorResponse(c, http.StatusLocked, &apperrors.AppError{
			Code:    string(apperrors.ErrAccountLocked.Code),
			Message: apperrors.ErrAccountLocked.Message,
			Details: fmt.Sprintf("Account locked until %s (%.0f minutes remaining)",
				user.LockedUntil.Format(time.RFC3339), lockRemaining.Minutes()),
		})
		return
	}
	log.Printf("LOGIN: Account not locked, checking password")

	// Check password
	log.Printf("LOGIN: Calling CheckPassword")
	if !CheckPassword(password, user.Password) {
		log.Printf("LOGIN: Password check failed")
		// Record failed login attempt
		if err := RecordFailedLogin(database.DB, &user); err != nil {
			utils.HandleError(err, fmt.Sprintf("Failed to record failed login for user %s", user.Email))
		}
		// Record failed attempt for enhanced rate limiting
		middleware.RecordFailedLoginAttempt(c)

		if IsAccountLocked(&user) {
			utils.SendErrorResponse(c, http.StatusLocked, &apperrors.AppError{
				Code:    string(apperrors.ErrAccountLocked.Code),
				Message: apperrors.ErrAccountLocked.Message,
				Details: fmt.Sprintf("Account locked until %s", user.LockedUntil.Format(time.RFC3339)),
			})
		} else {
			respondInvalidCredentials(c)
		}
		return
	}
	log.Printf("LOGIN: Password check passed")

	// Check MFA if enabled
	if user.MFAEnabled {
		mfaValid := false

		// Check TOTP code
		if req.TOTPCode != "" && user.MFASecret != "" {
			mfaValid = ValidateTOTP(user.MFASecret, req.TOTPCode)
		}

		// Check backup code if TOTP failed
		if !mfaValid && req.BackupCode != "" {
			mfaValid = ValidateBackupCode(&user, req.BackupCode)
		}

		if !mfaValid {
			if err := RecordFailedLogin(database.DB, &user); err != nil {
				utils.HandleError(err, fmt.Sprintf("Failed to record failed MFA for user %s", user.Email))
			}

			if IsAccountLocked(&user) {
				utils.SendErrorResponse(c, http.StatusLocked, &apperrors.AppError{
					Code:    string(apperrors.ErrAccountLocked.Code),
					Message: apperrors.ErrAccountLocked.Message,
					Details: fmt.Sprintf("Account locked until %s", user.LockedUntil.Format(time.RFC3339)),
				})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":        "Invalid MFA verification code",
					"mfa_required": true,
				})
			}
			return
		}
	}

	// Record successful login (resets failed attempts)
	if err := RecordSuccessfulLogin(database.DB, &user); err != nil {
		log.Printf("Failed to record successful login for user %s: %v", user.Email, err)
	}
	// Record successful attempt for enhanced rate limiting
	middleware.RecordSuccessfulLoginAttempt(c)

	// Get user's organization (for now, get the first one they're a member of)
	var member models.OrganizationMember
	if err := database.DB.Preload("Organization").Where("user_id = ? AND status = ?", user.ID, "active").First(&member).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No active organization found"})
		return
	}

	// TODO: Create Redis session if available
	// This will be handled when session management is extracted to a separate package
	sessionID := GenerateSessionID()

	// Generate JWT token and set secure cookies
	token, expiry, csrfToken, err := GenerateToken(user, member.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	SetAuthCookie(c, token, expiry, csrfToken)
	c.Header("X-CSRF-Token", csrfToken)

	// Generate refresh token cookie
	refreshToken, refreshExpiry, err := GenerateRefreshToken(user.ID, member.OrganizationID)
	if err != nil {
		log.Printf("Failed to generate refresh token for user %s: %v", user.Email, err)
	} else {
		SetRefreshCookie(c, refreshToken, refreshExpiry)
	}

	responseBody := gin.H{
		"message":      "Login successful",
		"user":         gin.H{"id": user.ID, "name": user.Name, "email": user.Email, "role": user.Role, "mfa_enabled": user.MFAEnabled},
		"organization": gin.H{"id": member.Organization.ID, "name": member.Organization.Name},
		"session_id":   sessionID,
		"csrf_token":   csrfToken,
		"expires_at":   expiry.Unix(),
		"token":        token,
	}

	if refreshToken != "" {
		responseBody["refresh_token"] = refreshToken
		responseBody["refresh_expires_at"] = refreshExpiry.Unix()
	}

	c.JSON(http.StatusOK, responseBody)
	log.Printf("LOGIN completed for %s in %v", user.Email, time.Since(start))
}

// HandleRegister handles user registration
func HandleRegister(c *gin.Context) {
	// Check if registration is disabled
	if os.Getenv("DISABLE_REGISTRATION") == "true" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "User registration is disabled. Please contact an administrator.",
		})
		return
	}

	// Get validated values from context
	email := utils.GetValidatedString(c, "validated_email")
	password := utils.GetValidatedString(c, "validated_password")
	name := utils.GetValidatedString(c, "validated_name")
	organizationName := utils.GetValidatedString(c, "validated_organization_name")

	if email == "" || password == "" || name == "" || organizationName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "All fields are required"})
		return
	}

	// Check if user already exists
	var existingUser models.User
	if err := database.DB.Where("email = ?", email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists"})
		return
	}

	// Hash password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Generate email verification token
	emailToken := GenerateToken64()

	// Create user
	user := models.User{
		Name:             name,
		Email:            email,
		Password:         hashedPassword,
		Role:             "owner", // First user in organization becomes owner
		EmailVerifyToken: emailToken,
		TrialEndsAt:      GetTrialEndDate(),
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Create organization
	organization := models.Organization{
		Name:    organizationName,
		OwnerID: user.ID,
	}

	if err := database.DB.Create(&organization).Error; err != nil {
		// Clean up user if organization creation fails
		database.DB.Delete(&user)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization"})
		return
	}

	// Create organization member record
	member := models.OrganizationMember{
		OrganizationID: organization.ID,
		UserID:         user.ID,
		Role:           "owner",
		Status:         "active",
		JoinedAt:       &time.Time{},
	}
	now := time.Now()
	member.JoinedAt = &now

	database.DB.Create(&member)

	c.JSON(http.StatusCreated, gin.H{
		"message":      "User registered successfully",
		"user":         gin.H{"id": user.ID, "name": user.Name, "email": user.Email},
		"organization": gin.H{"id": organization.ID, "name": organization.Name},
	})
}

// HandleLogout handles user logout
func HandleLogout(c *gin.Context) {
	// TODO: Handle Redis session cleanup when session management is extracted

	tokenString := c.GetString("token")
	if tokenString == "" {
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
				tokenString = tokenParts[1]
			}
		}
	}
	if tokenString == "" {
		if cookieToken, err := c.Cookie(AuthCookieName); err == nil {
			tokenString = cookieToken
		}
	}
	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No active session found"})
		return
	}

	// Parse token to get expiry time
	claims, err := ParseToken(tokenString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		return
	}

	// Add token to blacklist with its expiry time
	BlacklistToken(database.DB, tokenString, claims.ExpiresAt.Time)
	ClearAuthCookie(c)

	// TODO: Remove refresh token from vault when session management is extracted
	ClearRefreshCookie(c)

	userID := c.GetUint("user_id")
	orgID := c.GetUint("organization_id")
	if userID != 0 {
		if err := RevokeAllDatabaseSessionsForUser(userID, orgID); err != nil {
			log.Printf("Warning: Failed to revoke database sessions for user %d: %v", userID, err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// respondInvalidCredentials sends an invalid credentials error response
func respondInvalidCredentials(c *gin.Context) {
	utils.SendErrorResponse(c, http.StatusUnauthorized, &apperrors.AppError{
		Code:    string(apperrors.ErrInvalidCredentials.Code),
		Message: apperrors.ErrInvalidCredentials.Message,
	})
}


// HandleGetProfile retrieves the current user's profile
func HandleGetProfile(c *gin.Context) {
	userID := c.GetUint("user_id")
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Get user's organizations
	var memberships []models.OrganizationMember
	if err := database.DB.Preload("Organization").Where("user_id = ? AND status = ?", userID, "active").Find(&memberships).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organizations"})
		return
	}

	organizations := make([]gin.H, len(memberships))
	for i, membership := range memberships {
		organizations[i] = gin.H{
			"id":   membership.Organization.ID,
			"name": membership.Organization.Name,
			"role": membership.Role,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":             user.ID,
			"name":           user.Name,
			"email":          user.Email,
			"role":           user.Role,
			"email_verified": user.EmailVerified,
			"mfa_enabled":    user.MFAEnabled,
			"trial_ends_at":  user.TrialEndsAt,
			"created_at":     user.CreatedAt,
		},
		"organizations": organizations,
	})
}

// HandleUpdateProfile updates the user's profile
func HandleUpdateProfile(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("user_id")

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.Name = req.Name
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
		"user":    gin.H{"id": user.ID, "name": user.Name, "email": user.Email},
	})
}

// HandleChangePassword changes the user's password
func HandleChangePassword(c *gin.Context) {
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("user_id")

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check current password
	if !CheckPassword(req.CurrentPassword, user.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Current password is incorrect"})
		return
	}

	// Hash new password
	hashedPassword, err := HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = hashedPassword
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Revoke all existing tokens for this user
	RevokeAllUserTokens(user.ID)

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully. Please log in again."})
}

// HandleVerifyEmail verifies a user's email address
func HandleVerifyEmail(c *gin.Context) {
	token := strings.TrimSpace(c.Query("token"))

	if token == "" {
		var req struct {
			Token string `json:"token"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
			return
		}

		token = strings.TrimSpace(req.Token)
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
			return
		}
	}

	var user models.User
	if err := database.DB.Where("email_verify_token = ? AND email_verified = ?", token, false).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification token"})
		return
	}

	user.EmailVerified = true
	user.EmailVerifyToken = ""

	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// HandleRequestPasswordReset sends a password reset link
func HandleRequestPasswordReset(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := database.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Don't reveal if email exists or not for security
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset link has been sent"})
		return
	}

	// Generate reset token with expiration
	resetToken := GenerateToken64()
	tokenExpiry := time.Now().Add(1 * time.Hour) // Token expires in 1 hour
	user.PasswordResetToken = resetToken
	user.PasswordResetExpiry = &tokenExpiry

	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset token"})
		return
	}

	// TODO: Send email with reset link
	c.JSON(http.StatusOK, gin.H{"message": "Password reset link sent to email"})
}

// HandleResetPassword resets a user's password using a token
func HandleResetPassword(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := database.DB.Where("password_reset_token = ?", req.Token).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired token"})
		return
	}

	// Check if token has expired
	if user.PasswordResetExpiry == nil || time.Now().After(*user.PasswordResetExpiry) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password reset token has expired. Please request a new one."})
		return
	}

	// Hash new password
	hashedPassword, err := HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = hashedPassword
	user.PasswordResetToken = ""
	user.PasswordResetExpiry = nil

	// Reset failed login attempts on successful password reset
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	user.LastFailedLogin = nil

	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// HandleSetupMFA initiates MFA setup by generating a QR code
func HandleSetupMFA(c *gin.Context) {
	userID := c.GetUint("user_id")

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.MFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is already enabled"})
		return
	}

	// Generate new TOTP secret
	key, err := GenerateMFASecret(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate MFA secret"})
		return
	}

	// Generate backup codes
	backupCodes, err := GenerateBackupCodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	// Save secret (but don't enable MFA yet)
	user.MFASecret = key.Secret()
	user.MFABackupCodes = HashBackupCodes(backupCodes)
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save MFA setup"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"qr_code":      key.String(), // This contains the QR code URL
		"secret":       key.Secret(),
		"backup_codes": backupCodes,
		"message":      "Scan the QR code with your authenticator app, then verify with a code to enable MFA",
	})
}

// HandleEnableMFA verifies TOTP code and enables MFA
func HandleEnableMFA(c *gin.Context) {
	var req struct {
		TOTPCode string `json:"totp_code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("user_id")

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.MFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is already enabled"})
		return
	}

	if user.MFASecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA setup not initiated. Call /mfa/setup first"})
		return
	}

	// Verify TOTP code
	if !ValidateTOTP(user.MFASecret, req.TOTPCode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid TOTP code"})
		return
	}

	// Enable MFA
	user.MFAEnabled = true
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable MFA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA enabled successfully",
	})
}

// HandleDisableMFA disables MFA after verification
func HandleDisableMFA(c *gin.Context) {
	var req struct {
		Password   string `json:"password" binding:"required"`
		TOTPCode   string `json:"totp_code,omitempty"`
		BackupCode string `json:"backup_code,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("user_id")

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.MFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is not enabled"})
		return
	}

	// Verify password
	if !CheckPassword(req.Password, user.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password"})
		return
	}

	// Verify MFA (either TOTP or backup code)
	mfaValid := false
	if req.TOTPCode != "" && user.MFASecret != "" {
		mfaValid = ValidateTOTP(user.MFASecret, req.TOTPCode)
	}
	if !mfaValid && req.BackupCode != "" {
		mfaValid = ValidateBackupCode(&user, req.BackupCode)
	}

	if !mfaValid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA verification required"})
		return
	}

	// Disable MFA
	user.MFAEnabled = false
	user.MFASecret = ""
	user.MFABackupCodes = []string{}
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable MFA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled successfully"})
}

// HandleRegenerateBackupCodes generates new MFA backup codes
func HandleRegenerateBackupCodes(c *gin.Context) {
	var req struct {
		Password   string `json:"password" binding:"required"`
		TOTPCode   string `json:"totp_code,omitempty"`
		BackupCode string `json:"backup_code,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("user_id")

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.MFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is not enabled"})
		return
	}

	// Verify password
	if !CheckPassword(req.Password, user.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password"})
		return
	}

	// Verify MFA (either TOTP or backup code)
	mfaValid := false
	if req.TOTPCode != "" && user.MFASecret != "" {
		mfaValid = ValidateTOTP(user.MFASecret, req.TOTPCode)
	}
	if !mfaValid && req.BackupCode != "" {
		mfaValid = ValidateBackupCode(&user, req.BackupCode)
	}

	if !mfaValid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA verification required"})
		return
	}

	// Generate new backup codes
	newBackupCodes, err := GenerateBackupCodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	user.MFABackupCodes = HashBackupCodes(newBackupCodes)
	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save backup codes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"backup_codes": newBackupCodes,
		"message":      "New backup codes generated successfully. Save them in a secure location.",
	})
}

// HandleGetCSRFToken generates and returns a CSRF token
func HandleGetCSRFToken(c *gin.Context) {
	log.Println("DEBUG: getCSRFToken invoked")
	// Generate CSRF token
	csrfBytes := make([]byte, 32)
	rand.Read(csrfBytes)
	csrfToken := hex.EncodeToString(csrfBytes)

	// Set CSRF token in httpOnly cookie
	csrfCookie := &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		Expires:  time.Now().Add(time.Hour),
		MaxAge:   3600,
		HttpOnly: false,
		Secure:   shouldUseSecureCookies(c),  // From cookies.go
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, csrfCookie)

	c.JSON(http.StatusOK, gin.H{"csrf_token": csrfToken})
	log.Println("DEBUG: getCSRFToken responded")
}

// HandleGetUserPermissions returns the current user's permissions
func HandleGetUserPermissions(c *gin.Context) {
	userID := c.GetUint("user_id")
	organizationID := c.GetUint("organization_id")

	var permissions []models.Permission
	if err := database.DB.Where("user_id = ? AND organization_id = ?", userID, organizationID).Find(&permissions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"permissions": permissions,
	})
}

// HandleGetRoleDefinitions returns available role definitions
func HandleGetRoleDefinitions(c *gin.Context) {
	// Define standard roles
	roles := []gin.H{
		{
			"name":        "owner",
			"description": "Full access to organization resources",
			"permissions": []string{"*"},
		},
		{
			"name":        "admin",
			"description": "Administrative access to organization resources",
			"permissions": []string{"clusters:*", "users:read", "users:invite"},
		},
		{
			"name":        "member",
			"description": "Standard member access",
			"permissions": []string{"clusters:read", "clusters:connect"},
		},
		{
			"name":        "viewer",
			"description": "Read-only access",
			"permissions": []string{"clusters:read"},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"roles": roles,
	})
}

// HandleGetUserRoleAssignment returns the user's role in the current organization
func HandleGetUserRoleAssignment(c *gin.Context) {
	userID := c.GetUint("user_id")
	organizationID := c.GetUint("organization_id")

	var member models.OrganizationMember
	if err := database.DB.Where("user_id = ? AND organization_id = ?", userID, organizationID).First(&member).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Membership not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":         userID,
		"organization_id": organizationID,
		"role":            member.Role,
		"status":          member.Status,
		"joined_at":       member.JoinedAt,
	})
}
