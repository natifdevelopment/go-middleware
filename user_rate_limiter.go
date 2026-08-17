package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// UserRateLimiter enforces per-user rate limiting using Redis as the
// shared counter store. This ensures rate limits are enforced across
// all pods (not per-pod like the in-memory IPRateLimiter).
//
// Two tiers are supported:
//   - Per-user: limits authenticated users by their user ID
//   - Per-IP:   limits unauthenticated requests by client IP
//
// The limiter uses a sliding window counter algorithm with Redis INCR +
// EXPIRE, which is atomic and efficient.
type UserRateLimiter struct {
	client      *redis.Client
	keyPrefix   string
	limitPerMin int           // max requests per minute
	blockPeriod time.Duration // how long to block after limit exceeded
}

// NewUserRateLimiter creates a Redis-backed rate limiter.
//
// Usage:
//
//	limiter := middleware.NewUserRateLimiter(redisClient, 300, 5*time.Minute)
//	r.Use(middleware.UserRateLimitMiddleware(limiter))
func NewUserRateLimiter(client *redis.Client, limitPerMin int, blockPeriod time.Duration) *UserRateLimiter {
	if limitPerMin <= 0 {
		limitPerMin = 300 // 300 req/min = 5 req/s default
	}
	if blockPeriod <= 0 {
		blockPeriod = 5 * time.Minute
	}
	// Use a per-limit key prefix so different tiers (read/write/upload/sensitive)
	// do not share the same Redis counter. Without this, a burst of GET requests
	// can exhaust the upload tier limit and cause 429s on multipart uploads.
	return &UserRateLimiter{
		client:      client,
		keyPrefix:   fmt.Sprintf("ratelimit:limit%d", limitPerMin),
		limitPerMin: limitPerMin,
		blockPeriod: blockPeriod,
	}
}

// UserRateLimitMiddleware returns a Gin middleware that enforces per-user
// (authenticated) and per-IP (unauthenticated) rate limiting using Redis.
//
// The middleware checks for a user ID in the gin context (set by auth
// middleware). If no user ID is found, it falls back to IP-based limiting.
//
// Rate limit headers are added to the response:
//   - X-RateLimit-Limit:     max requests per minute
//   - X-RateLimit-Remaining: remaining requests in current window
//   - X-RateLimit-Reset:     seconds until window resets
//   - Retry-After:           seconds until retry (only when blocked)
func UserRateLimitMiddleware(limiter *UserRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limiter == nil || limiter.client == nil {
			c.Next()
			return
		}

		// Determine identifier: user ID if authenticated, otherwise IP
		identifier := c.GetString("user_id")
		idType := "user"
		if identifier == "" {
			identifier = c.ClientIP()
			idType = "ip"
		}

		ctx := context.Background()
		now := time.Now().UTC()
		windowKey := fmt.Sprintf("%s:%s:%s:%d", limiter.keyPrefix, idType, identifier, now.Unix()/60)
		blockKey := fmt.Sprintf("%s:block:%s:%s", limiter.keyPrefix, idType, identifier)

		// Check if currently blocked
		blocked, err := limiter.client.Exists(ctx, blockKey).Result()
		if err == nil && blocked > 0 {
			ttl, _ := limiter.client.TTL(ctx, blockKey).Result()
			retryAfter := int(ttl.Seconds())
			if retryAfter <= 0 {
				retryAfter = 60
			}
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.limitPerMin))
			c.Header("X-RateLimit-Remaining", "0")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"status":  false,
				"message": "Rate limit exceeded. Please try again later.",
				"meta": gin.H{
					"retryAfter": retryAfter,
					"limit":      limiter.limitPerMin,
				},
			})
			c.Abort()
			return
		}

		// Increment counter for current window
		count, err := limiter.client.Incr(ctx, windowKey).Result()
		if err != nil {
			// Redis down — fail open (allow request, log error)
			c.Next()
			return
		}

		// Set expiry on first request in window
		if count == 1 {
			limiter.client.Expire(ctx, windowKey, 60*time.Second)
		}

		// Set rate limit headers
		remaining := limiter.limitPerMin - int(count)
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.limitPerMin))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", "60")

		// Check if limit exceeded
		if int(count) > limiter.limitPerMin {
			// Block the identifier
			limiter.client.Set(ctx, blockKey, "1", limiter.blockPeriod)

			retryAfter := int(limiter.blockPeriod.Seconds())
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"status":  false,
				"message": "Rate limit exceeded. Please try again later.",
				"meta": gin.H{
					"retryAfter": retryAfter,
					"limit":      limiter.limitPerMin,
				},
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// TieredRateLimitConfig defines different rate limits for different
// endpoint categories.
type TieredRateLimitConfig struct {
	// Default rate for all endpoints (requests per minute)
	Default int
	// Sensitive endpoints: login, forgot-password, OTP (requests per minute)
	Sensitive int
	// Write endpoints: POST/PUT/DELETE (requests per minute)
	Write int
	// Read endpoints: GET (requests per minute)
	Read int
	// Upload endpoints: file uploads (requests per minute)
	Upload int
}

// DefaultTieredRateLimitConfig returns sensible defaults.
//   - Default: 300 req/min (5 req/s)
//   - Sensitive: 10 req/min (login, OTP)
//   - Write: 100 req/min (create, update, delete)
//   - Read: 600 req/min (list, get)
//   - Upload: 20 req/min (file uploads)
func DefaultTieredRateLimitConfig() TieredRateLimitConfig {
	return TieredRateLimitConfig{
		Default:   300,
		Sensitive: 10,
		Write:     100,
		Read:      600,
		Upload:    20,
	}
}

// TieredRateLimitMiddleware returns a Gin middleware that applies
// different rate limits based on the request method and path.
// Sensitive endpoints (login, OTP, forgot-password) get the strictest limits.
func TieredRateLimitMiddleware(client *redis.Client, config TieredRateLimitConfig) gin.HandlerFunc {
	if config.Default <= 0 {
		config = DefaultTieredRateLimitConfig()
	}

	// Create limiters for each tier
	defaultLimiter := NewUserRateLimiter(client, config.Default, 5*time.Minute)
	sensitiveLimiter := NewUserRateLimiter(client, config.Sensitive, 15*time.Minute)
	writeLimiter := NewUserRateLimiter(client, config.Write, 5*time.Minute)
	readLimiter := NewUserRateLimiter(client, config.Read, 1*time.Minute)
	uploadLimiter := NewUserRateLimiter(client, config.Upload, 10*time.Minute)

	sensitivePaths := map[string]bool{
		"/login":           true,
		"/auth/login":      true,
		"/forgot-password": true,
		"/auth/forgot":     true,
		"/otp":             true,
		"/auth/otp":        true,
		"/activate":        true,
		"/auth/activate":   true,
		"/reset-password":  true,
		"/auth/reset":      true,
		"/refresh-token":   true,
		"/auth/refresh":    true,
		// TOTP / authenticator endpoints — strict limit (10 req/min) to
		// prevent brute-force of 6-digit codes (1M combinations).
		"/totp/verify-setup":                 true,
		"/auth/totp/verify-setup":            true,
		"/totp/disable":                      true,
		"/auth/totp/disable":                 true,
		"/totp/regenerate-backup-codes":      true,
		"/auth/totp/regenerate-backup-codes": true,
		"/totp/setup":                        true,
		"/auth/totp/setup":                   true,
	}

	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		// Check if path is sensitive
		for suffix := range sensitivePaths {
			if pathMatchesSensitive(path, suffix) {
				UserRateLimitMiddleware(sensitiveLimiter)(c)
				return
			}
		}

		// Check if upload (multipart form)
		contentType := c.GetHeader("Content-Type")
		if strings.Contains(contentType, "multipart/form-data") {
			UserRateLimitMiddleware(uploadLimiter)(c)
			return
		}

		// Check method
		method := c.Request.Method
		switch method {
		case "GET":
			UserRateLimitMiddleware(readLimiter)(c)
		case "POST", "PUT", "PATCH", "DELETE":
			UserRateLimitMiddleware(writeLimiter)(c)
		default:
			UserRateLimitMiddleware(defaultLimiter)(c)
		}
	}
}

// pathMatchesSensitive checks if the request path ends with the given
// sensitive suffix or has it as a complete path segment. This prevents
// false positives like "/auth/login/init" matching "/auth/login".
func pathMatchesSensitive(path, suffix string) bool {
	if path == suffix {
		return true
	}
	// Match if path ends with "/<suffix>" (suffix is a full final segment).
	if len(path) > len(suffix) && path[len(path)-len(suffix)-1] == '/' && path[len(path)-len(suffix):] == suffix {
		return true
	}
	return false
}
