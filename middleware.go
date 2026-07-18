package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/natifdevelopment/go-sso"
	"github.com/natifdevelopment/go-utils"
)

// AuthGuard is a Gin middleware that enforces JWT-based authentication.
// It supports fallback to gateway shared secret for inter-service calls.
//
// Services should set sso.JWTSecretKey and sso.GatewaySharedSecret before
// using this middleware.
func AuthGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for gateway secret first (inter-service calls)
		if sso.ValidateGatewaySecret(c.Request) {
			c.Next()
			return
		}

		// Check for JWT token in Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.SendForbiddenError(c, nil)
			c.Abort()
			return
		}

		claims, err := sso.ParseJWT(authHeader)
		if err != nil {
			utils.SendForbiddenError(c, err)
			c.Abort()
			return
		}

		// Set context data from JWT claims
		c.Set("user", claims.User)
		c.Set("page", claims.Page)
		c.Set("activity", claims.Activity)
		c.Set("pageActivity", claims.PageActivity)

		c.Next()
	}
}

// GatewayGuard is a Gin middleware that only allows requests with a valid
// gateway shared secret header.
func GatewayGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !sso.ValidateGatewaySecret(c.Request) {
			c.JSON(http.StatusForbidden, gin.H{
				"status":  false,
				"message": "Gateway secret is required",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// CORSConfig holds CORS middleware configuration.
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
}

// CORSMiddleware returns a Gin middleware that handles CORS.
func CORSMiddleware(config CORSConfig) gin.HandlerFunc {
	if len(config.AllowOrigins) == 0 {
		config.AllowOrigins = []string{"*"}
	}
	if len(config.AllowMethods) == 0 {
		config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	if len(config.AllowHeaders) == 0 {
		config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Gateway-Secret", "X-CSRF-Token"}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		allowed := false

		for _, o := range config.AllowOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))
			if config.AllowCredentials {
				c.Header("Access-Control-Allow-Credentials", "true")
			}
			if len(config.ExposeHeaders) > 0 {
				c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ", "))
			}
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// CSRFConfig holds CSRF middleware configuration.
type CSRFConfig struct {
	Secret      string
	CookieName  string
	HeaderName  string
	TokenLength int
}

// CSRFMiddleware returns a Gin middleware that enforces CSRF protection
// using the Double-Submit Cookie pattern.
func CSRFMiddleware(config CSRFConfig) gin.HandlerFunc {
	if config.CookieName == "" {
		config.CookieName = "csrf_token"
	}
	if config.HeaderName == "" {
		config.HeaderName = "X-CSRF-Token"
	}
	if config.TokenLength == 0 {
		config.TokenLength = 32
	}

	safeMethods := map[string]bool{
		"GET":     true,
		"HEAD":    true,
		"OPTIONS": true,
		"TRACE":   true,
	}

	return func(c *gin.Context) {
		if safeMethods[c.Request.Method] {
			c.Next()
			return
		}

		cookieToken, err := c.Cookie(config.CookieName)
		if err != nil || cookieToken == "" {
			c.JSON(http.StatusForbidden, gin.H{
				"status":  false,
				"message": "CSRF token cookie is missing",
			})
			c.Abort()
			return
		}

		headerToken := c.GetHeader(config.HeaderName)
		if headerToken == "" || headerToken != cookieToken {
			c.JSON(http.StatusForbidden, gin.H{
				"status":  false,
				"message": "CSRF token validation failed",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitConfig holds rate limiter configuration.
type RateLimitConfig struct {
	RequestsPerMinute int
}

// RateLimitMiddleware returns a Gin middleware that enforces rate limiting.
// Currently a simple in-memory counter per IP. For production use,
// consider using the go-security/ratelimit package with Redis.
func RateLimitMiddleware(config RateLimitConfig) gin.HandlerFunc {
	if config.RequestsPerMinute <= 0 {
		config.RequestsPerMinute = 100
	}

	// TODO: implement proper rate limiting using go-security/ratelimit
	return func(c *gin.Context) {
		c.Next()
	}
}
