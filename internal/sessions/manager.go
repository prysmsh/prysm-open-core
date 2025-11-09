package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"prysm-backend/internal/database"
	"prysm-backend/internal/models"
)

// Manager handles session management with Redis
type Manager struct {
	client  *redis.Client
	ctx     context.Context
	timeout time.Duration
}

// Data represents session information stored in Redis
type Data struct {
	UserID         uint      `json:"user_id"`
	OrganizationID uint      `json:"organization_id"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
	LastAccessed   time.Time `json:"last_accessed"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	IsActive       bool      `json:"is_active"`
}

// Config holds Redis configuration
type Config struct {
	Host             string
	Port             string
	Password         string
	DB               int
	TTL              time.Duration
	OperationTimeout time.Duration
}

// Global session manager
var GlobalManager *Manager

func (sm *Manager) withTimeout() (context.Context, context.CancelFunc) {
	timeout := sm.timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return context.WithTimeout(sm.ctx, timeout)
}

func wrapRedisError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s redis operation timed out: %w", operation, err)
	}
	return fmt.Errorf("%s redis operation failed: %w", operation, err)
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// InitManager initializes the Redis session manager
func InitManager() error {
	timeoutMS := getEnvInt("SESSION_REDIS_TIMEOUT_MS", 1500)
	if timeoutMS <= 0 {
		timeoutMS = 1500
	}

	config := Config{
		Host:             getEnvWithDefault("REDIS_HOST", "localhost"),
		Port:             getEnvWithDefault("REDIS_PORT", "6379"),
		Password:         getEnvWithDefault("REDIS_PASSWORD", ""),
		DB:               getEnvInt("REDIS_DB", 0),
		TTL:              time.Duration(getEnvInt("SESSION_TTL_HOURS", 24)) * time.Hour,
		OperationTimeout: time.Duration(timeoutMS) * time.Millisecond,
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	})

	// Test connection
	ctx := context.Background()
	pingCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	defer cancel()
	_, err := rdb.Ping(pingCtx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}

	GlobalManager = &Manager{
		client:  rdb,
		ctx:     ctx,
		timeout: config.OperationTimeout,
	}

	log.Println("✅ Redis session manager initialized")
	return nil
}

// CreateSession creates a new session in Redis
func (sm *Manager) CreateSession(sessionID string, userID uint, organizationID uint, email, role, ipAddress, userAgent string) error {
	sessionData := Data{
		UserID:         userID,
		OrganizationID: organizationID,
		Email:          email,
		Role:           role,
		CreatedAt:      time.Now(),
		LastAccessed:   time.Now(),
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		IsActive:       true,
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %v", err)
	}

	// Store session with TTL
	ttl := time.Duration(getEnvInt("SESSION_TTL_HOURS", 24)) * time.Hour
	ctx, cancel := sm.withTimeout()
	err = sm.client.Set(ctx, "session:"+sessionID, data, ttl).Err()
	cancel()
	if err != nil {
		return wrapRedisError("store session", err)
	}

	// Also store user session mapping for quick lookup
	userSessionKey := fmt.Sprintf("user_sessions:%d", userID)
	ctx, cancel = sm.withTimeout()
	err = sm.client.SAdd(ctx, userSessionKey, sessionID).Err()
	cancel()
	if err != nil {
		log.Printf("Warning: failed to store user session mapping: %v", wrapRedisError("store user session mapping", err))
	}

	// Set TTL for user session mapping
	ctx, cancel = sm.withTimeout()
	err = sm.client.Expire(ctx, userSessionKey, ttl).Err()
	cancel()
	if err != nil {
		log.Printf("Warning: failed to set TTL for user session mapping: %v", wrapRedisError("expire user session mapping", err))
	}

	return nil
}

// GetSession retrieves session data from Redis
func (sm *Manager) GetSession(sessionID string) (*Data, error) {
	ctx, cancel := sm.withTimeout()
	data, err := sm.client.Get(ctx, "session:"+sessionID).Result()
	cancel()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, wrapRedisError("get session", err)
	}

	var sessionData Data
	err = json.Unmarshal([]byte(data), &sessionData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %v", err)
	}

	// Update last accessed time
	sessionData.LastAccessed = time.Now()
	if err := sm.UpdateSession(sessionID, &sessionData); err != nil {
		log.Printf("Warning: failed to refresh session %s: %v", sessionID, err)
	}

	return &sessionData, nil
}

// UpdateSession updates session data in Redis
func (sm *Manager) UpdateSession(sessionID string, sessionData *Data) error {
	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %v", err)
	}

	ttl := time.Duration(getEnvInt("SESSION_TTL_HOURS", 24)) * time.Hour
	ctx, cancel := sm.withTimeout()
	err = sm.client.Set(ctx, "session:"+sessionID, data, ttl).Err()
	cancel()
	if err != nil {
		return wrapRedisError("update session", err)
	}

	return nil
}

// DeleteSession removes a session from Redis
func (sm *Manager) DeleteSession(sessionID string) error {
	ctx, cancel := sm.withTimeout()
	err := sm.client.Del(ctx, "session:"+sessionID).Err()
	cancel()
	if err != nil {
		return wrapRedisError("delete session", err)
	}
	return nil
}

// GetActiveSessions retrieves all active sessions for a user
func (sm *Manager) GetActiveSessions(userID uint) ([]Data, error) {
	userSessionKey := fmt.Sprintf("user_sessions:%d", userID)
	ctx, cancel := sm.withTimeout()
	sessionIDs, err := sm.client.SMembers(ctx, userSessionKey).Result()
	cancel()
	if err != nil {
		return nil, wrapRedisError("get user sessions", err)
	}

	sessions := make([]Data, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		sessionData, err := sm.GetSession(sessionID)
		if err != nil {
			log.Printf("Warning: failed to get session %s: %v", sessionID, err)
			continue
		}
		sessions = append(sessions, *sessionData)
	}

	return sessions, nil
}

// Additional session handlers extracted from auth.go

// HandleGetUserActiveSessions returns active sessions for the current user
func HandleGetUserActiveSessions(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	limitVal, err := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if err != nil || limitVal <= 0 {
		limitVal = 50
	}
	if limitVal > 200 {
		limitVal = 200
	}

	status := strings.TrimSpace(c.DefaultQuery("status", "active"))
	query := database.DB.Where("organization_id = ?", orgID)
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var sessionRecords []models.Session
	if err := query.Order("created_at DESC").Limit(limitVal).Find(&sessionRecords).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sessions"})
		return
	}

	response := make([]gin.H, len(sessionRecords))
	for i, session := range sessionRecords {
		response[i] = sessionToResponse(session)
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": response,
		"total":    len(response),
	})
}

// HandleGetUserSession returns a specific session
func HandleGetUserSession(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	sessionID := c.Param("sessionId")

	sessionRecord, err := findSessionByIdentifier(orgID, sessionID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session": sessionToResponse(*sessionRecord),
	})
}

// HandleEndUserSession ends a specific session
func HandleEndUserSession(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	sessionID := c.Param("sessionId")
	sessionRecord, err := updateSessionStatus(orgID, sessionID, "revoked")
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Session ended successfully",
		"session_id": sessionID,
		"session":    sessionToResponse(*sessionRecord),
	})
}

// HandleRevokeSession revokes a specific session
func HandleRevokeSession(c *gin.Context) {
	HandleEndUserSession(c)
}

// HandleRevokeAllSessions revokes all user sessions
func HandleRevokeAllSessions(c *gin.Context) {
	orgID := c.GetUint("organization_id")
	userID := c.GetUint("user_id")

	result := database.DB.Model(&models.Session{}).
		Where("organization_id = ? AND user_id = ? AND status = ?", orgID, userID, "active").
		Updates(map[string]interface{}{
			"status":   "revoked",
			"end_time": time.Now(),
		})

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke sessions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "All sessions revoked successfully",
		"user_id":          userID,
		"sessions_revoked": result.RowsAffected,
	})
}

// DeleteAllUserSessions deletes all sessions for a user
func (sm *Manager) DeleteAllUserSessions(userID uint) error {
	userSessionKey := fmt.Sprintf("user_sessions:%d", userID)
	ctx, cancel := sm.withTimeout()
	sessionIDs, err := sm.client.SMembers(ctx, userSessionKey).Result()
	cancel()
	if err != nil {
		return wrapRedisError("get user sessions", err)
	}

	for _, sessionID := range sessionIDs {
		if err := sm.DeleteSession(sessionID); err != nil {
			log.Printf("Warning: failed to delete session %s: %v", sessionID, err)
		}
	}

	// Remove user session mapping
	ctx, cancel = sm.withTimeout()
	err = sm.client.Del(ctx, userSessionKey).Err()
	cancel()
	if err != nil {
		return wrapRedisError("delete user session mapping", err)
	}

	return nil
}

func sessionToResponse(session models.Session) gin.H {
	payload := gin.H{
		"id":              session.ID,
		"session_id":      session.SessionID,
		"user_id":         session.UserID,
		"cluster_id":      session.ClusterID,
		"status":          session.Status,
		"created_at":      session.CreatedAt,
		"updated_at":      session.UpdatedAt,
		"end_time":        session.EndTime,
		"duration":        session.Duration,
		"commands":        session.CommandsRun,
		"credential":      session.CredentialType,
		"ip_address":      session.CredentialRef,
		"user_agent":      session.CredentialType,
		"organization_id": session.OrganizationID,
	}
	return payload
}

func findSessionByIdentifier(orgID uint, identifier string) (*models.Session, error) {
	query := database.DB.Where("organization_id = ?", orgID)
	if id, err := strconv.ParseUint(identifier, 10, 64); err == nil {
		query = query.Where("id = ? OR session_id = ?", id, identifier)
	} else {
		query = query.Where("session_id = ?", identifier)
	}

	var session models.Session
	if err := query.First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func updateSessionStatus(orgID uint, identifier string, status string) (*models.Session, error) {
	session, err := findSessionByIdentifier(orgID, identifier)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session.Status = status
	session.EndTime = &now

	if err := database.DB.Save(session).Error; err != nil {
		return nil, err
	}
	return session, nil
}
