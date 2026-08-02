package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// IdempotencyConfig holds configuration for the idempotency middleware.
type IdempotencyConfig struct {
	// HeaderName is the HTTP header to check for the idempotency key.
	// Default: "Idempotency-Key"
	HeaderName string
	// TTL is how long to store idempotent responses in Redis.
	// Default: 24h (24 hours)
	TTL time.Duration
	// KeyPrefix is the Redis key prefix for idempotency entries.
	// Default: "idempotency:"
	KeyPrefix string
}

// DefaultIdempotencyConfig returns sensible defaults.
func DefaultIdempotencyConfig() IdempotencyConfig {
	return IdempotencyConfig{
		HeaderName: "Idempotency-Key",
		TTL:        24 * time.Hour,
		KeyPrefix:  "idempotency:",
	}
}

// idempotentResponse is the cached response stored in Redis.
type idempotentResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// idempotentBuffer captures the response body for caching.
type idempotentBuffer struct {
	gin.ResponseWriter
	buf    bytes.Buffer
	status int
}

func (w *idempotentBuffer) Write(b []byte) (int, error) {
	w.buf.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *idempotentBuffer) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *idempotentBuffer) WriteString(s string) (int, error) {
	w.buf.WriteString(s)
	return w.ResponseWriter.WriteString(s)
}

// IdempotencyMiddleware prevents duplicate processing of POST/PUT/DELETE
// requests by caching responses keyed on the Idempotency-Key header.
//
// If a request with the same Idempotency-Key is received within the TTL
// window, the cached response is returned without re-executing the handler.
//
// Requests without an Idempotency-Key header pass through normally.
// GET requests are not cached (use the cache middleware for that).
//
// Usage:
//
//	r.POST("/payments", idempotency.IdempotencyMiddleware(redisClient, idempotency.DefaultIdempotencyConfig()), h.Create)
func IdempotencyMiddleware(redisClient *redis.Client, cfg IdempotencyConfig) gin.HandlerFunc {
	if cfg.HeaderName == "" {
		cfg = DefaultIdempotencyConfig()
	}
	if cfg.TTL == 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "idempotency:"
	}

	return func(c *gin.Context) {
		// Skip if no Redis client
		if redisClient == nil {
			c.Next()
			return
		}

		// Only apply to write methods
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// Skip if no idempotency key provided (optional middleware)
		idempotencyKey := c.GetHeader(cfg.HeaderName)
		if idempotencyKey == "" {
			c.Next()
			return
		}

		ctx := context.Background()
		redisKey := cfg.KeyPrefix + idempotencyKey

		// Check if we have a cached response for this idempotency key
		val, err := redisClient.Get(ctx, redisKey).Bytes()
		if err == nil {
			var cached idempotentResponse
			if json.Unmarshal(val, &cached) == nil {
				c.Data(cached.Status, "application/json", cached.Body)
				return
			}
		}

		// Try to acquire a lock (SETNX) to prevent concurrent duplicate
		// requests from both executing. If lock fails, wait briefly and
		// re-check cache.
		locked, err := redisClient.SetNX(ctx, redisKey+":lock", "1", 30*time.Second).Result()
		if err == nil && !locked {
			// Another request is processing — wait and re-check cache
			time.Sleep(100 * time.Millisecond)
			if val, err := redisClient.Get(ctx, redisKey).Bytes(); err == nil {
				var cached idempotentResponse
				if json.Unmarshal(val, &cached) == nil {
					c.Data(cached.Status, "application/json", cached.Body)
					return
				}
			}
			// Still no cached response — proceed (rare race condition)
		}
		defer func() {
			_ = redisClient.Del(ctx, redisKey+":lock").Err()
		}()

		// Read and buffer the request body so it can be replayed if needed
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.Next()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Execute handler and capture response
		buf := &idempotentBuffer{ResponseWriter: c.Writer}
		c.Writer = buf
		c.Next()

		// Cache successful responses (2xx)
		if buf.status >= 200 && buf.status < 300 {
			cached := idempotentResponse{
				Status: buf.status,
				Body:   buf.buf.Bytes(),
			}
			if data, err := json.Marshal(cached); err == nil {
				_ = redisClient.Set(ctx, redisKey, data, cfg.TTL).Err()
			}
		}
	}
}
