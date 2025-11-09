package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
	"prysm-backend/pkg/utils"
)

// EnhancedRateLimiter provides sophisticated rate limiting with multiple tiers
type EnhancedRateLimiter struct {
	loginLimiter         *IPRateLimiter
	registerLimiter      *IPRateLimiter
	passwordResetLimiter *IPRateLimiter
	generalLimiter       *IPRateLimiter
	apiLimiter           *IPRateLimiter
	failedAttempts       map[string]*FailedAttemptTracker
	mu                   sync.RWMutex
}

// FailedAttemptTracker tracks failed attempts for progressive rate limiting
type FailedAttemptTracker struct {
	Count        int
	LastFailed   time.Time
	BlockedUntil *time.Time
}

// IPRateLimiter manages rate limiters per IP
type IPRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

// GetLimiter returns the rate limiter for an IP
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(i.rate, i.burst)
		i.limiters[ip] = limiter
	}

	return limiter
}

// NewEnhancedRateLimiter creates a new enhanced rate limiter
func NewEnhancedRateLimiter() *EnhancedRateLimiter {
	return &EnhancedRateLimiter{
		loginLimiter:         NewIPRateLimiter(rate.Every(time.Minute), 5),
		registerLimiter:      NewIPRateLimiter(rate.Every(5*time.Minute), 3),
		passwordResetLimiter: NewIPRateLimiter(rate.Every(10*time.Minute), 2),
		generalLimiter:       NewIPRateLimiter(rate.Every(time.Second), 30),
		apiLimiter:           NewIPRateLimiter(rate.Every(time.Second), 100),
		failedAttempts:       make(map[string]*FailedAttemptTracker),
	}
}

// Global enhanced rate limiter
var enhancedLimiter = NewEnhancedRateLimiter()

func (erl *EnhancedRateLimiter) GetProgressiveDelay(ip string) time.Duration {
	erl.mu.RLock()
	tracker, exists := erl.failedAttempts[ip]
	erl.mu.RUnlock()

	if !exists {
		return 0
	}

	if tracker.BlockedUntil != nil && time.Now().Before(*tracker.BlockedUntil) {
		return time.Until(*tracker.BlockedUntil)
	}

	switch {
	case tracker.Count >= 10:
		return 30 * time.Minute
	case tracker.Count >= 5:
		return 10 * time.Minute
	case tracker.Count >= 3:
		return 5 * time.Minute
	case tracker.Count >= 1:
		return 1 * time.Minute
	default:
		return 0
	}
}

func (erl *EnhancedRateLimiter) RecordFailedAttempt(ip string) (bool, *time.Time, int) {
	erl.mu.Lock()
	defer erl.mu.Unlock()

	tracker, exists := erl.failedAttempts[ip]
	if !exists {
		tracker = &FailedAttemptTracker{}
		erl.failedAttempts[ip] = tracker
	}

	tracker.Count++
	tracker.LastFailed = time.Now()
	prevBlocked := tracker.BlockedUntil != nil && time.Now().Before(*tracker.BlockedUntil)
	var newlyBlocked bool
	var blockedUntil *time.Time

	if os.Getenv("DISABLE_PROGRESSIVE_LOGIN_DELAY") != "true" {
		var delay time.Duration
		switch {
		case tracker.Count >= 10:
			delay = 30 * time.Minute
		case tracker.Count >= 5:
			delay = 10 * time.Minute
		case tracker.Count >= 3:
			delay = 5 * time.Minute
		case tracker.Count >= 1:
			delay = 1 * time.Minute
		default:
			delay = 0
		}
		if delay > 0 {
			blockedUntil := time.Now().Add(delay)
			tracker.BlockedUntil = &blockedUntil
			if !prevBlocked {
				newlyBlocked = true
			}
		} else {
			tracker.BlockedUntil = nil
		}
	}

	if tracker.BlockedUntil != nil {
		blockedUntil = tracker.BlockedUntil
	}

	return newlyBlocked, blockedUntil, tracker.Count
}

func (erl *EnhancedRateLimiter) RecordSuccessfulAttempt(ip string) {
	erl.mu.Lock()
	defer erl.mu.Unlock()

	if tracker, exists := erl.failedAttempts[ip]; exists {
		tracker.Count = 0
		tracker.BlockedUntil = nil
	}
}

func (erl *EnhancedRateLimiter) IsBlocked(ip string) bool {
	erl.mu.RLock()
	defer erl.mu.RUnlock()

	tracker, exists := erl.failedAttempts[ip]
	if !exists {
		return false
	}

	return tracker.BlockedUntil != nil && time.Now().Before(*tracker.BlockedUntil)
}

func (erl *EnhancedRateLimiter) CleanupExpiredEntries() {
	erl.mu.Lock()
	defer erl.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for ip, tracker := range erl.failedAttempts {
		if tracker.LastFailed.Before(cutoff) {
			delete(erl.failedAttempts, ip)
		}
	}
}

// Middleware functions

func buildLoginRateLimitKey(c *gin.Context) string {
	email := strings.ToLower(c.GetString("validated_email"))
	if email == "" {
		return getClientIP(c)
	}
	sum := sha256.Sum256([]byte(email))
	return hex.EncodeToString(sum[:])
}

func LoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)
		key := buildLoginRateLimitKey(c)
		if key == "" {
			key = ip
		}

		log.Printf("LoginRateLimit: Checking rate limit for key=%s, ip=%s", key, ip)

		log.Printf("LoginRateLimit: About to check IsBlocked for key=%s", key)
		isBlocked := enhancedLimiter.IsBlocked(key)
		log.Printf("LoginRateLimit: IsBlocked returned %v for key=%s", isBlocked, key)

		if isBlocked {
			delay := enhancedLimiter.GetProgressiveDelay(key)
			log.Printf("LoginRateLimit: Key %s is blocked for %v", key, delay)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":         "Too many failed login attempts. IP temporarily blocked.",
				"retry_after":   fmt.Sprintf("%.0f seconds", delay.Seconds()),
				"blocked_until": time.Now().Add(delay).Format(time.RFC3339),
			})
			c.Abort()
			return
		}

		limiter := enhancedLimiter.loginLimiter.GetLimiter(key)
		if !limiter.Allow() {
			log.Printf("LoginRateLimit: Rate limit exceeded for key=%s", key)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many login attempts. Please try again later.",
				"retry_after": "60 seconds",
			})
			c.Abort()
			return
		}

		log.Printf("LoginRateLimit: Allowing request for key=%s", key)
		c.Next()
	}
}

func RegisterRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)

		if enhancedLimiter.IsBlocked(ip) {
			delay := enhancedLimiter.GetProgressiveDelay(ip)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many failed attempts. IP temporarily blocked.",
				"retry_after": fmt.Sprintf("%.0f seconds", delay.Seconds()),
			})
			c.Abort()
			return
		}

		limiter := enhancedLimiter.registerLimiter.GetLimiter(ip)
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many registration attempts. Please try again later.",
				"retry_after": "5 minutes",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func PasswordResetRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)

		if enhancedLimiter.IsBlocked(ip) {
			delay := enhancedLimiter.GetProgressiveDelay(ip)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many failed attempts. IP temporarily blocked.",
				"retry_after": fmt.Sprintf("%.0f seconds", delay.Seconds()),
			})
			c.Abort()
			return
		}

		limiter := enhancedLimiter.passwordResetLimiter.GetLimiter(ip)
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many password reset attempts. Please try again later.",
				"retry_after": "10 minutes",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func APIRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)

		if enhancedLimiter.IsBlocked(ip) {
			delay := enhancedLimiter.GetProgressiveDelay(ip)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many failed attempts. IP temporarily blocked.",
				"retry_after": fmt.Sprintf("%.0f seconds", delay.Seconds()),
			})
			c.Abort()
			return
		}

		limiter := enhancedLimiter.apiLimiter.GetLimiter(ip)
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many API requests. Please slow down.",
				"retry_after": "1 second",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func GeneralRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip rate limiting for health check and agent endpoints
		path := c.Request.URL.Path
		if path == "/health" || path == "/metrics" || path == "/api/v1/health" ||
			path == "/api/v1/logs/ingest/v1/logs" || strings.HasPrefix(path, "/api/v1/clusters/") ||
			strings.HasPrefix(path, "/api/v1/internal/") || strings.HasPrefix(path, "/api/v1/auth/") {
			c.Next()
			return
		}

		ip := getClientIP(c)
		log.Printf("GeneralRateLimit: Checking rate limit for path=%s, ip=%s", path, ip)

		if enhancedLimiter.IsBlocked(ip) {
			delay := enhancedLimiter.GetProgressiveDelay(ip)
			log.Printf("GeneralRateLimit: IP %s is blocked for %v", ip, delay)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many failed attempts. IP temporarily blocked.",
				"retry_after": fmt.Sprintf("%.0f seconds", delay.Seconds()),
			})
			c.Abort()
			return
		}

		limiter := enhancedLimiter.generalLimiter.GetLimiter(ip)
		if !limiter.Allow() {
			log.Printf("GeneralRateLimit: Rate limit exceeded for ip=%s", ip)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many requests. Please slow down.",
				"retry_after": "1 second",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RecordFailedLoginAttempt records a failed login attempt
func RecordFailedLoginAttempt(c *gin.Context) {
	key := buildLoginRateLimitKey(c)
	if key == "" {
		key = getClientIP(c)
	}
	if blocked, blockedUntil, count := enhancedLimiter.RecordFailedAttempt(key); blocked {
		extras := map[string]interface{}{
			"login_key":       key,
			"client_ip":       getClientIP(c),
			"failed_attempts": count,
		}
		if email := strings.ToLower(c.GetString("validated_email")); email != "" {
			extras["email"] = email
		}
		if blockedUntil != nil {
			extras["blocked_until"] = blockedUntil.Format(time.RFC3339)
		}
		utils.CaptureSentryError(c, nil, "rate_limit.login_blocked", extras)
	}
}

// RecordSuccessfulLoginAttempt resets failed login tracking
func RecordSuccessfulLoginAttempt(c *gin.Context) {
	key := buildLoginRateLimitKey(c)
	if key == "" {
		key = getClientIP(c)
	}
	enhancedLimiter.RecordSuccessfulAttempt(key)
}

// StartCleanup starts the cleanup routine for expired entries
func StartCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				utils.CaptureSentryPanic("middleware.StartCleanup", r)
			}
		}()
		for range ticker.C {
			enhancedLimiter.CleanupExpiredEntries()
		}
	}()
}

func getClientIP(c *gin.Context) string {
	// Try CF-Connecting-IP header first (Cloudflare)
	if cfIP := c.GetHeader("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// Try X-Forwarded-For header
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP header
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	return c.ClientIP()
}
