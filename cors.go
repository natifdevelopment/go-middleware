package middleware

import (
	"net/http"
	"strings"

	config "github.com/natifdevelopment/go-config"
	"github.com/gin-gonic/gin"
	securitycors "github.com/natifdevelopment/go-security/cors"
)

// CorsMiddleware returns a CORS middleware that uses the go-security/cors
// implementation for richer, security-hardened CORS handling.
func CorsMiddleware(cfg config.CorsConfig) gin.HandlerFunc {
	allowCreds := false
	for _, v := range cfg.AllowCredentials {
		if strings.EqualFold(strings.TrimSpace(v), "true") {
			allowCreds = true
			break
		}
	}
	if allowCreds {
		for _, o := range cfg.AllowOrigins {
			if o == "*" {
				allowCreds = false
				break
			}
		}
	}
	corsCfg := securitycors.New().With(
		securitycors.WithAllowOrigins(cfg.AllowOrigins...),
		securitycors.WithAllowMethods(cfg.AllowMethods...),
		securitycors.WithAllowHeaders(cfg.AllowHeaders...),
		securitycors.WithExposeHeaders(cfg.ExposeHeaders...),
		securitycors.WithAllowCredentials(allowCreds),
	)
	mw, err := securitycors.Middleware(corsCfg)
	if err != nil {
		return func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{"status": false, "message": "CORS configuration error"})
			c.Abort()
		}
	}
	return func(c *gin.Context) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { c.Next() })
		mw(next).ServeHTTP(c.Writer, c.Request)
	}
}
