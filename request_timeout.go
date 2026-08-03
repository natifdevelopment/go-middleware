package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestTimeoutConfig holds configuration for the request timeout middleware.
type RequestTimeoutConfig struct {
	// Timeout is the maximum duration for a request before it's cancelled.
	// Default: 30s
	Timeout time.Duration
	// UploadTimeout is the timeout for requests with multipart/form-data
	// or large content bodies (file uploads). Default: 120s
	UploadTimeout time.Duration
	// UploadSizeThreshold is the body size (bytes) above which UploadTimeout
	// is used instead of Timeout. Default: 1MB (1 << 20)
	UploadSizeThreshold int64
}

// DefaultRequestTimeoutConfig returns sensible defaults.
func DefaultRequestTimeoutConfig() RequestTimeoutConfig {
	return RequestTimeoutConfig{
		Timeout:             30 * time.Second,
		UploadTimeout:       120 * time.Second,
		UploadSizeThreshold: 1 << 20, // 1MB
	}
}

// RequestTimeoutMiddleware sets a deadline on the request context so that
// long-running handlers are cancelled automatically. This prevents goroutine
// leaks and cascade failures when a downstream dependency (DB, Redis, external
// API) hangs.
//
// The timeout context propagates to gorm (via db.WithContext) and go-redis
// (via cmd.SetCtx) calls that use c.Request.Context().
//
// Usage:
//
//	r.Use(commonmiddleware.RequestTimeoutMiddleware(commonmiddleware.DefaultRequestTimeoutConfig()))
func RequestTimeoutMiddleware(cfg RequestTimeoutConfig) gin.HandlerFunc {
	if cfg.Timeout <= 0 {
		cfg = DefaultRequestTimeoutConfig()
	}
	if cfg.UploadTimeout <= 0 {
		cfg.UploadTimeout = 120 * time.Second
	}
	if cfg.UploadSizeThreshold <= 0 {
		cfg.UploadSizeThreshold = 1 << 20
	}

	return func(c *gin.Context) {
		timeout := cfg.Timeout

		// Use longer timeout for file uploads
		contentType := c.GetHeader("Content-Type")
		if contentType == "multipart/form-data" ||
			c.Request.ContentLength > cfg.UploadSizeThreshold {
			timeout = cfg.UploadTimeout
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		// Process request — if it exceeds the timeout, the context is
		// cancelled and downstream operations (DB, Redis, HTTP) will
		// receive ctx.Err() == context.DeadlineExceeded.
		c.Next()

		// If the context was cancelled by our timeout (not by client
		// disconnect), return 504 Gateway Timeout if no response was
		// written yet.
		if ctx.Err() == context.DeadlineExceeded && c.Writer.Status() == 0 {
			c.JSON(http.StatusGatewayTimeout, gin.H{
				"status":  "error",
				"message": "request timeout",
			})
		}
	}
}
