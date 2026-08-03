package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	config "github.com/natifdevelopment/go-config"
)

// CsrfMiddleware validates the X-CSRF-Token header against the cookie token
// for mutating HTTP methods. Endpoints ending with /init are exempt because
// they are token-issuance endpoints. Requests signed with X-Gateway-Signature
// (trusted internal calls from the gateway or master-api) are also exempt —
// they are authenticated via HMAC, not browser cookies, so CSRF does not apply.
func CsrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// /init endpoints are CSRF token issuers — they cannot require a token to issue one.
		if strings.HasSuffix(c.Request.URL.Path, "/init") {
			c.Next()
			return
		}

		// Trusted internal service-to-service calls signed with X-Gateway-Signature
		// are not browser-originated, so CSRF protection does not apply. The
		// AuthGuard middleware downstream validates the HMAC signature.
		if c.GetHeader("X-Gateway-Signature") != "" && c.GetHeader("X-Gateway-Timestamp") != "" {
			c.Next()
			return
		}

		// Validate token on POST, PUT, PATCH, and DELETE requests.
		if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut ||
			c.Request.Method == http.MethodPatch || c.Request.Method == http.MethodDelete {

			csrfToken := c.GetHeader("X-CSRF-Token")
			csrfCookieName := "csrf_token"
			if config.COOKIE_PREFIX != "" {
				csrfCookieName = config.COOKIE_PREFIX + "_csrf_token"
			}
			cookieToken, err := c.Cookie(csrfCookieName)

			if err != nil || csrfToken == "" || csrfToken != cookieToken {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
				return
			}
		}

		c.Next()
	}
}
