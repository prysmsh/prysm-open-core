package auth

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	AuthCookieName    = "prysm_session"
	CSRFCookieName    = "prysm_csrf"
	RefreshCookieName = "prysm_refresh"
)

func shouldUseSecureCookies(c *gin.Context) bool {
	if value := strings.ToLower(strings.TrimSpace(os.Getenv("SECURE_COOKIES"))); value != "" {
		return value != "false"
	}
	if c != nil {
		if proto := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto"))); proto == "https" {
			return true
		}
	}
	return c.Request.TLS != nil
}

// SetAuthCookie sets authentication and CSRF cookies
func SetAuthCookie(c *gin.Context, token string, expiry time.Time, csrfToken string) {
	cookie := &http.Cookie{
		Name:     AuthCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		MaxAge:   int(time.Until(expiry).Seconds()),
		HttpOnly: true,
		Secure:   shouldUseSecureCookies(c),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, cookie)

	csrfCookie := &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		Expires:  expiry,
		MaxAge:   int(time.Until(expiry).Seconds()),
		HttpOnly: false,
		Secure:   shouldUseSecureCookies(c),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, csrfCookie)
}

// SetRefreshCookie sets a refresh token cookie
func SetRefreshCookie(c *gin.Context, token string, expiry time.Time) {
	refreshCookie := &http.Cookie{
		Name:     RefreshCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		MaxAge:   int(time.Until(expiry).Seconds()),
		HttpOnly: true,
		Secure:   shouldUseSecureCookies(c),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, refreshCookie)
}

// ClearAuthCookie clears authentication cookies
func ClearAuthCookie(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   shouldUseSecureCookies(c),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, cookie)

	csrfCookie := &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   shouldUseSecureCookies(c),
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(c.Writer, csrfCookie)
}

// ClearRefreshCookie clears the refresh token cookie
func ClearRefreshCookie(c *gin.Context) {
	refreshCookie := &http.Cookie{
		Name:     RefreshCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   shouldUseSecureCookies(c),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, refreshCookie)
}

