package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// IPRateLimiter limits requests per IP address for public (unauthenticated) endpoints.
// Designed for sensitive endpoints such as activation, forgot-password, and OTP flows.
type IPRateLimiter struct {
	mu          sync.Mutex
	ipRequests  map[string][]time.Time // IP -> request timestamps within window
	blockedIPs  map[string]time.Time   // IP -> block expiry time
	limit       int                    // max requests per window
	window      time.Duration          // sliding window duration
	blockPeriod time.Duration          // how long to block after limit exceeded
}

// NewIPRateLimiter creates an in-memory per-IP rate limiter.
func NewIPRateLimiter(limit int, window time.Duration, blockPeriod time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		ipRequests:  make(map[string][]time.Time),
		blockedIPs:  make(map[string]time.Time),
		limit:       limit,
		window:      window,
		blockPeriod: blockPeriod,
	}
}

func (r *IPRateLimiter) isBlocked(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if expiry, exists := r.blockedIPs[ip]; exists && time.Now().UTC().Before(expiry) {
		return true
	}
	delete(r.blockedIPs, ip)
	return false
}

func (r *IPRateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	cutoff := now.Add(-r.window)

	// keep only requests within the window
	var recent []time.Time
	for _, t := range r.ipRequests[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= r.limit {
		r.blockedIPs[ip] = now.Add(r.blockPeriod)
		delete(r.ipRequests, ip)
		return false
	}

	r.ipRequests[ip] = append(recent, now)
	return true
}

// IPRateLimitMiddleware returns a Gin middleware that enforces per-IP rate limiting.
// Suitable for public endpoints where no authenticated user ID is available.
func IPRateLimitMiddleware(limiter *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if limiter.isBlocked(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"status":  false,
				"message": "Terlalu banyak percobaan. Silakan coba lagi nanti.",
			})
			c.Abort()
			return
		}

		if !limiter.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"status":  false,
				"message": "Terlalu banyak percobaan. Silakan coba lagi nanti.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
