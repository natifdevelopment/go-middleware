package middleware

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxSizeMiddleware limits the size of incoming requests to maxBytes megabytes.
// It wraps the request body with http.MaxBytesReader and aborts with 413 if the
// body is too large.
func MaxSizeMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes*1024*1024)
		if err := c.Request.ParseForm(); err != nil {
			if err == http.ErrNotMultipart {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"status": false, "message": "Request body too large"})
				c.Abort()
				return
			}
			if err == io.EOF || err.Error() == "http: request body too large" {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"status": false, "message": "Request body too large"})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
