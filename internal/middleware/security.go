package middleware

import (
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// SecurityHeaders adds comprehensive security headers
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"font-src 'self' data:; " +
			"connect-src 'self' ws: wss:; " +
			"frame-ancestors 'none'; " +
			"base-uri 'self'; " +
			"form-action 'self'; " +
			"object-src 'none'; " +
			"media-src 'self'; " +
			"worker-src 'self'; " +
			"manifest-src 'self'; " +
			"upgrade-insecure-requests;"

		if os.Getenv("ENVIRONMENT") == "development" || os.Getenv("ENVIRONMENT") == "dev" {
			c.Header("Content-Security-Policy-Report-Only", csp)
		} else {
			c.Header("Content-Security-Policy", csp)
		}

		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "0")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
		c.Header("Cross-Origin-Opener-Policy", "same-origin")
		c.Header("Cross-Origin-Embedder-Policy", "require-corp")
		c.Header("Cross-Origin-Resource-Policy", "same-origin")
		c.Header("Server", "")
		c.Header("X-Powered-By", "")

		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}

		c.Next()
	}
}

// RequestSizeLimit limits request body size to prevent DoS
func RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if websocket.IsWebSocketUpgrade(c.Request) {
			c.Next()
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}

// CSRFProtection implements CSRF protection
func CSRFProtection(authCookieName, csrfCookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}

		if strings.HasPrefix(c.Request.URL.Path, "/api/v1/auth/login") {
			c.Next()
			return
		}

		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			c.Next()
			return
		}

		if _, err := c.Cookie(authCookieName); err != nil {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		if method == http.MethodGet && (path == "/api/v1/csrf-token" || path == "/api/v1/auth/csrf-token") {
			c.Next()
			return
		}

		headerToken := strings.TrimSpace(c.GetHeader("X-CSRF-Token"))
		if headerToken == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Missing CSRF token"})
			c.Abort()
			return
		}

		cookieToken, err := c.Cookie(csrfCookieName)
		if err != nil || cookieToken == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Missing CSRF cookie"})
			c.Abort()
			return
		}

		if subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookieToken)) != 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// InputSanitization sanitizes user inputs
func InputSanitization() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, values := range c.Request.URL.Query() {
			for i, value := range values {
				values[i] = sanitizeInput(value)
			}
		}
		c.Next()
	}
}

// IPWhitelist restricts access to specific IPs
func IPWhitelist(allowedIPs []string, enforce bool) gin.HandlerFunc {
	normalized := make([]string, 0, len(allowedIPs))
	for _, entry := range allowedIPs {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}

	if !enforce || len(normalized) == 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	ipSet, networks := buildIPWhitelist(normalized)

	return func(c *gin.Context) {
		// When behind Cloudflare, check the CF-Connecting-IP instead
		clientIP := ""
		remoteAddr := c.Request.RemoteAddr
		cfConnectingIP := c.GetHeader("CF-Connecting-IP")
		xForwardedFor := c.GetHeader("X-Forwarded-For")
		xRealIP := c.GetHeader("X-Real-IP")
		
		if os.Getenv("BEHIND_CLOUDFLARE") == "true" {
			// For Cloudflare, trust the CF-Connecting-IP header for the real client IP
			if cfConnectingIP != "" {
				clientIP = strings.TrimSpace(cfConnectingIP)
			}
		}
		
		// If not behind Cloudflare or header not found, use regular detection
		if clientIP == "" {
			clientIP = getClientIP(c)
		}

		// Debug logging
		log.Printf("IPWhitelist Debug: RemoteAddr=%s, CF-Connecting-IP=%s, X-Forwarded-For=%s, X-Real-IP=%s, ClientIP=%s, BEHIND_CLOUDFLARE=%s", 
			remoteAddr, cfConnectingIP, xForwardedFor, xRealIP, clientIP, os.Getenv("BEHIND_CLOUDFLARE"))

		if clientIP == "" {
			log.Printf("IPWhitelist: No client IP found, blocking request")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied from this IP"})
			c.Abort()
			return
		}

		if _, ok := ipSet[clientIP]; ok {
			c.Next()
			return
		}

		parsedIP := net.ParseIP(clientIP)
		if parsedIP != nil {
			if ipv4 := parsedIP.To4(); ipv4 != nil {
				parsedIP = ipv4
			}

			for _, network := range networks {
				if network.Contains(parsedIP) {
					c.Next()
					return
				}
			}
		}

		log.Printf("Access denied by IP whitelist: client_ip=%s (not in allowed list)", clientIP)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied from this IP"})
		c.Abort()
	}
}


// SecurityMonitoring logs security events
func SecurityMonitoring() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		isWebSocketRequest := websocket.IsWebSocketUpgrade(c.Request)

		userAgent := c.GetHeader("User-Agent")
		isAgentEndpoint := strings.HasPrefix(c.Request.URL.Path, "/api/v1/clusters/ping")

		if !isAgentEndpoint && isSuspiciousUserAgent(userAgent) {
			log.Printf("🚨 Suspicious User-Agent detected: %s from IP: %s", userAgent, getClientIP(c))
		}

		c.Next()

		duration := time.Since(start)
		if !isWebSocketRequest && duration > 5*time.Second {
			log.Printf("⚠️ Slow request: %s %s took %v from IP: %s",
				c.Request.Method, c.Request.URL.Path, duration, getClientIP(c))
		}

		if c.Writer.Status() >= 400 {
			log.Printf("🚨 Error response: %d %s %s from IP: %s",
				c.Writer.Status(), c.Request.Method, c.Request.URL.Path, getClientIP(c))
		}
	}
}

// Helper functions

func sanitizeInput(input string) string {
	dangerousChars := regexp.MustCompile(`[<>'"&;|` + "`" + `$(){}[\]\\*?~]`)
	sanitized := dangerousChars.ReplaceAllString(input, "")
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")
	return strings.TrimSpace(sanitized)
}

func isSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"sqlmap", "nmap", "nikto", "w3af", "burp", "zap",
		"bot", "crawler", "spider", "scanner",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	return false
}

func buildIPWhitelist(entries []string) (map[string]struct{}, []*net.IPNet) {
	ipSet := make(map[string]struct{})
	var networks []*net.IPNet

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		switch {
		case entry == "localhost":
			ipSet["127.0.0.1"] = struct{}{}
			ipSet["::1"] = struct{}{}
		case strings.Contains(entry, "/"):
			if _, network, err := net.ParseCIDR(entry); err == nil {
				networks = append(networks, network)
			}
		default:
			if ip := net.ParseIP(entry); ip != nil {
				ipSet[ip.String()] = struct{}{}
			}
		}
	}

	// Always allow loopback
	ipSet["127.0.0.1"] = struct{}{}
	ipSet["::1"] = struct{}{}

	// Add Cloudflare IP ranges when behind Cloudflare
	if os.Getenv("BEHIND_CLOUDFLARE") == "true" {
		cloudflareRanges := []string{
			"173.245.48.0/20",
			"103.21.244.0/22",
			"103.22.200.0/22",
			"103.31.4.0/22",
			"141.101.64.0/18",
			"108.162.192.0/18",
			"190.93.240.0/20",
			"188.114.96.0/20",
			"197.234.240.0/22",
			"198.41.128.0/17",
			"162.158.0.0/15",
			"104.16.0.0/13",
			"104.24.0.0/14",
			"172.64.0.0/13",
			"131.0.72.0/22",
		}
		for _, cidr := range cloudflareRanges {
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				networks = append(networks, network)
			}
		}
	}

	return ipSet, networks
}

// GetSecurityConfig returns security configuration from environment
type SecurityConfig struct {
	MaxRequestSize     int64
	AllowedIPs         []string
	EnforceIPWhitelist bool
}

func GetSecurityConfig() SecurityConfig {
	config := SecurityConfig{
		MaxRequestSize: 10 * 1024 * 1024, // 10MB default
	}

	if maxSize := os.Getenv("MAX_REQUEST_SIZE"); maxSize != "" {
		if size, err := strconv.ParseInt(maxSize, 10, 64); err == nil {
			config.MaxRequestSize = size
		}
	}

	if allowedIPs := os.Getenv("ALLOWED_IPS"); allowedIPs != "" {
		config.AllowedIPs = strings.FieldsFunc(allowedIPs, func(r rune) bool {
			return r == ',' || r == '\n' || r == ' '
		})
	}

	if enforce := os.Getenv("ENFORCE_IP_WHITELIST"); enforce != "" {
		config.EnforceIPWhitelist = enforce == "true" || enforce == "1"
	}

	return config
}

