package utils

import (
	"fmt"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
)

// CaptureSentryError reports an error or message to Sentry, enriching it with request metadata when available.
func CaptureSentryError(c *gin.Context, err error, message string, extras map[string]interface{}) {
	if err == nil && message == "" {
		return
	}

	hub := sentry.CurrentHub()
	if c != nil {
		if ctxHub := sentrygin.GetHubFromContext(c); ctxHub != nil {
			hub = ctxHub
		}
	}
	if hub == nil {
		return
	}

	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("service", "prysm-backend")
		if c != nil {
			scope.SetTag("http.method", c.Request.Method)
			scope.SetTag("http.path", c.FullPath())
			scope.SetExtra("request_url", c.Request.URL.String())
			scope.SetExtra("client_ip", c.ClientIP())
		}
		if message != "" {
			scope.SetExtra("context", message)
		}
		if extras != nil {
			for k, v := range extras {
				scope.SetExtra(k, v)
			}
		}

		if err != nil {
			scope.SetTag("sentry.capture_type", "exception")
			hub.CaptureException(err)
		} else {
			scope.SetTag("sentry.capture_type", "message")
			hub.CaptureMessage(message)
		}
	})
}

// CaptureSentryPanic converts a recovered panic into a Sentry event.
func CaptureSentryPanic(location string, recovered interface{}) {
	if recovered == nil {
		return
	}
	err := fmt.Errorf("panic recovered in %s: %v", location, recovered)
	CaptureSentryError(nil, err, location, map[string]interface{}{
		"panic_value": recovered,
	})
}
