package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"prysm-backend/internal/models"
)

// Run wires up the default organization, admin user, and any static agent tokens
// that we need for local Docker Compose stacks.
func Run(db *gorm.DB) {
	if db == nil {
		log.Println("bootstrap: skipping; database not initialized")
		return
	}

	org := ensureOrganization(db)
	if org == nil {
		log.Println("bootstrap: unable to ensure default organization")
		return
	}

	ensureAdminUser(db, org)
	seedAgentTokens(db, org.ID)
}

func ensureOrganization(db *gorm.DB) *models.Organization {
	orgIDStr := strings.TrimSpace(os.Getenv("BOOTSTRAP_ORG_ID"))
	if orgIDStr != "" {
		if orgID, err := strconv.ParseUint(orgIDStr, 10, 64); err == nil {
			var org models.Organization
			if err := db.First(&org, orgID).Error; err == nil {
				return &org
			}
		}
	}

	var org models.Organization
	if err := db.First(&org).Error; err == nil {
		return &org
	}

	name := strings.TrimSpace(os.Getenv("BOOTSTRAP_ORG_NAME"))
	if name == "" {
		name = "Prysm Demo Organization"
	}

	description := strings.TrimSpace(os.Getenv("BOOTSTRAP_ORG_DESCRIPTION"))

	org = models.Organization{
		Name:        name,
		Description: description,
	}
	if err := db.Create(&org).Error; err != nil {
		log.Printf("bootstrap: failed to create organization %q: %v", name, err)
		return nil
	}

	log.Printf("bootstrap: created organization %q (ID %d)", org.Name, org.ID)
	return &org
}

func ensureAdminUser(db *gorm.DB, org *models.Organization) {
	email := strings.TrimSpace(os.Getenv("ADMIN_EMAIL"))
	if email == "" {
		email = "admin@prysm.sh"
	}

	var user models.User
	if err := db.Where("email = ?", email).First(&user).Error; err == nil {
		ensureMembership(db, org, &user)
		if org.OwnerID == 0 {
			_ = db.Model(org).Update("owner_id", user.ID).Error
		}
		return
	}

	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		password = "Orbit#Nova42"
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("bootstrap: failed to hash admin password: %v", err)
		return
	}

	name := strings.TrimSpace(os.Getenv("ADMIN_NAME"))
	if name == "" {
		name = "System Administrator"
	}

	user = models.User{
		Email:         email,
		Password:      string(hashed),
		Name:          name,
		Role:          "admin",
		Active:        true,
		EmailVerified: true,
	}

	if err := db.Create(&user).Error; err != nil {
		log.Printf("bootstrap: failed to create admin user %s: %v", email, err)
		return
	}

	log.Printf("bootstrap: created admin user %s", email)
	ensureMembership(db, org, &user)
	_ = db.Model(org).Update("owner_id", user.ID).Error
}

func ensureMembership(db *gorm.DB, org *models.Organization, user *models.User) {
	var member models.OrganizationMember
	err := db.Where("organization_id = ? AND user_id = ?", org.ID, user.ID).First(&member).Error
	if err == nil {
		return
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		log.Printf("bootstrap: failed to check membership for user %d: %v", user.ID, err)
		return
	}

	now := time.Now()
	member = models.OrganizationMember{
		OrganizationID: org.ID,
		UserID:         user.ID,
		Role:           "owner",
		Status:         "active",
		JoinedAt:       &now,
	}
	if err := db.Create(&member).Error; err != nil {
		log.Printf("bootstrap: failed to create membership for user %d: %v", user.ID, err)
	}
}

func seedAgentTokens(db *gorm.DB, orgID uint) {
	tokens := collectBootstrapTokens()
	if len(tokens) == 0 {
		return
	}

	for idx, raw := range tokens {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		hash := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(hash[:])

		var existing models.AgentToken
		if err := db.Where("token_hash = ?", tokenHash).First(&existing).Error; err == nil {
			continue
		}

		prefix := token
		if len(prefix) > 8 {
			prefix = token[:8]
		}

		newToken := models.AgentToken{
			Name:           fmt.Sprintf("Bootstrap Agent Token %d", idx+1),
			TokenHash:      tokenHash,
			TokenPrefix:    prefix,
			OrganizationID: orgID,
			Permissions:    models.StringArray{"register", "ping", "update_data"},
			Active:         true,
		}

		if err := db.Create(&newToken).Error; err != nil {
			log.Printf("bootstrap: failed to seed agent token prefix %s…: %v", prefix, err)
			continue
		}

		log.Printf("bootstrap: seeded agent token with prefix %s…", prefix)
	}
}

func collectBootstrapTokens() []string {
	var tokens []string

	if env := strings.TrimSpace(os.Getenv("BOOTSTRAP_AGENT_TOKENS")); env != "" {
		for _, part := range strings.Split(env, ",") {
			if token := strings.TrimSpace(part); token != "" {
				tokens = append(tokens, token)
			}
		}
	}

	if len(tokens) == 0 {
		if fallback := strings.TrimSpace(os.Getenv("DEFAULT_AGENT_TOKEN")); fallback != "" {
			tokens = append(tokens, fallback)
		}
	}

	return tokens
}
