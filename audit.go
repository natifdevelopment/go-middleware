package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditAction represents the type of action being audited.
type AuditAction string

const (
	AuditActionCreate AuditAction = "CREATE"
	AuditActionUpdate AuditAction = "UPDATE"
	AuditActionDelete AuditAction = "DELETE"
	AuditActionLogin  AuditAction = "LOGIN"
	AuditActionLogout AuditAction = "LOGOUT"
	AuditActionExport AuditAction = "EXPORT"
	AuditActionImport AuditAction = "IMPORT"
	AuditActionUpload AuditAction = "UPLOAD"
	AuditActionDownload AuditAction = "DOWNLOAD"
)

// AuditLog represents an audit trail entry for sensitive operations.
// It records who did what, when, from where, and what changed.
type AuditLog struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID       *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"`
	UserName     string     `gorm:"type:varchar(255)" json:"user_name"`
	Action       AuditAction `gorm:"type:varchar(20);index" json:"action"`
	Resource     string     `gorm:"type:varchar(100);index" json:"resource"`
	ResourceID   string     `gorm:"type:varchar(255)" json:"resource_id,omitempty"`
	Method       string     `gorm:"type:varchar(10)" json:"method"`
	Path         string     `gorm:"type:text" json:"path"`
	StatusCode   int        `json:"status_code"`
	IPAddress    string     `gorm:"type:varchar(45)" json:"ip_address"`
	UserAgent    string     `gorm:"type:text" json:"user_agent"`
	RequestBody  string     `gorm:"type:text" json:"request_body,omitempty"`
	OldValues    string     `gorm:"type:text" json:"old_values,omitempty"`
	NewValues    string     `gorm:"type:text" json:"new_values,omitempty"`
	TraceID      string     `gorm:"type:varchar(64);index" json:"trace_id,omitempty"`
	Duration     int64      `json:"duration_ms"`
	CreatedAt    time.Time  `gorm:"autoCreateTime;index" json:"created_at"`
}

// TableName returns the database table name for audit logs.
func (AuditLog) TableName() string {
	return "t_audit_log"
}

// AuditConfig holds configuration for the audit middleware.
type AuditConfig struct {
	// DB is the GORM database connection for writing audit logs.
	DB *gorm.DB
	// SensitiveMethods defines which HTTP methods to audit (default: POST, PUT, PATCH, DELETE).
	SensitiveMethods map[string]bool
	// SensitivePaths defines additional paths to audit (e.g., GET /export).
	SensitivePaths map[string]bool
	// ExcludePaths defines paths to exclude from auditing (e.g., /health, /metrics).
	ExcludePaths map[string]bool
	// MaxBodySize is the max request body size to log (default: 4096 bytes).
	MaxBodySize int
	// SanitizeFields defines fields to mask in request body (e.g., password, token).
	SanitizeFields map[string]bool
}

// DefaultAuditConfig returns sensible defaults.
func DefaultAuditConfig(db *gorm.DB) AuditConfig {
	return AuditConfig{
		DB: db,
		SensitiveMethods: map[string]bool{
			http.MethodPost:   true,
			http.MethodPut:    true,
			http.MethodPatch:  true,
			http.MethodDelete: true,
		},
		SensitivePaths: map[string]bool{
			"/export": true,
			"/download": true,
		},
		ExcludePaths: map[string]bool{
			"/health":   true,
			"/metrics":  true,
			"/ready":    true,
			"/live":     true,
		},
		MaxBodySize: 4096,
		SanitizeFields: map[string]bool{
			"password":      true,
			"token":         true,
			"secret":        true,
			"api_key":       true,
			"private_key":   true,
			"credit_card":   true,
			"cvv":           true,
		},
	}
}

// AuditMiddleware returns a Gin middleware that logs sensitive operations
// to the database for audit trail purposes.
//
// The middleware:
//   - Captures the request body (for POST/PUT/PATCH/DELETE)
//   - Records who (user ID/name), what (action/resource), when (timestamp),
//     where (IP/path), and what changed (request body)
//   - Sanitizes sensitive fields (passwords, tokens) before logging
//   - Associates the audit entry with the trace_id for correlation
//   - Writes asynchronously to avoid blocking the response
//
// Usage:
//
//	r.Use(middleware.AuditMiddleware(middleware.DefaultAuditConfig(db)))
func AuditMiddleware(config AuditConfig) gin.HandlerFunc {
	if config.DB == nil {
		// No DB — skip auditing
		return func(c *gin.Context) { c.Next() }
	}

	// Auto-migrate the audit log table
	if err := config.DB.AutoMigrate(&AuditLog{}); err != nil {
		// Log warning but continue — don't block app startup
		fmt.Printf("[Audit] WARNING: AutoMigrate failed: %v\n", err)
	}

	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		// Skip excluded paths
		if config.ExcludePaths[path] {
			c.Next()
			return
		}

		method := c.Request.Method
		shouldAudit := config.SensitiveMethods[method] || isSensitivePath(path, config.SensitivePaths)

		if !shouldAudit {
			c.Next()
			return
		}

		// Capture request body for write operations
		var requestBody string
		if method != http.MethodGet && method != http.MethodHead && c.Request.Body != nil {
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err == nil {
				// Restore body for downstream handlers
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				if len(bodyBytes) <= config.MaxBodySize {
					requestBody = sanitizeBody(string(bodyBytes), config.SanitizeFields)
				} else {
					requestBody = fmt.Sprintf("[body too large: %d bytes]", len(bodyBytes))
				}
			}
		}

		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start).Milliseconds()

		// Determine action from method
		action := methodToAction(method)

		// Get user info from context (set by auth middleware)
		userID := getUserID(c)
		userName := getUserName(c)

		// Get resource ID from path params (if :id exists)
		resourceID := c.Param("id")
		if resourceID == "" {
			resourceID = c.Param("uuid")
		}

		// Get trace ID from context (set by tracing middleware)
		traceID := c.GetString("trace_id")

		// Create audit log entry
		audit := AuditLog{
			ID:          uuid.New(),
			UserID:      userID,
			UserName:    userName,
			Action:      action,
			Resource:    extractResource(path),
			ResourceID:  resourceID,
			Method:      method,
			Path:        path,
			StatusCode:  c.Writer.Status(),
			IPAddress:   c.ClientIP(),
			UserAgent:   c.Request.UserAgent(),
			RequestBody: requestBody,
			TraceID:     traceID,
			Duration:    duration,
			CreatedAt:   time.Now().UTC(),
		}

		// Write asynchronously — don't block response
		go func() {
			if err := config.DB.Create(&audit).Error; err != nil {
				// Log error but don't affect the response
				fmt.Printf("[Audit] ERROR: Failed to write audit log: %v\n", err)
			}
		}()

		// Also set audit info in response header for client-side correlation
		c.Header("X-Audit-Id", audit.ID.String())
	}
}

// methodToAction converts HTTP method to audit action.
func methodToAction(method string) AuditAction {
	switch method {
	case http.MethodPost:
		return AuditActionCreate
	case http.MethodPut, http.MethodPatch:
		return AuditActionUpdate
	case http.MethodDelete:
		return AuditActionDelete
	case http.MethodGet:
		return AuditActionDownload
	default:
		return AuditAction("OTHER")
	}
}

// extractResource extracts the resource name from the route path.
// e.g., "/api/v1/billing/propose-perhitungan/:id" → "propose-perhitungan"
func extractResource(path string) string {
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if p != "" && p != ":id" && p != ":uuid" && !strings.HasPrefix(p, ":") {
			return p
		}
	}
	return path
}

// isSensitivePath checks if a path matches any sensitive path pattern.
func isSensitivePath(path string, sensitivePaths map[string]bool) bool {
	for sp := range sensitivePaths {
		if strings.Contains(path, sp) {
			return true
		}
	}
	return false
}

// getUserID extracts user ID from gin context.
func getUserID(c *gin.Context) *uuid.UUID {
	idStr := c.GetString("user_id")
	if idStr == "" {
		return nil
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil
	}
	return &id
}

// getUserName extracts user name from gin context.
func getUserName(c *gin.Context) string {
	name := c.GetString("user_name")
	if name == "" {
		name = c.GetString("username")
	}
	return name
}

// sanitizeBody masks sensitive fields in the request body before logging.
func sanitizeBody(body string, sanitizeFields map[string]bool) string {
	if body == "" {
		return ""
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// Not JSON — return as-is (truncated)
		if len(body) > 500 {
			return body[:500] + "...[truncated]"
		}
		return body
	}

	sanitizeMap(data, sanitizeFields)

	sanitized, err := json.Marshal(data)
	if err != nil {
		return "[sanitization failed]"
	}
	return string(sanitized)
}

// sanitizeMap recursively masks sensitive fields in a map.
func sanitizeMap(data map[string]interface{}, sanitizeFields map[string]bool) {
	for key, value := range data {
		lowerKey := strings.ToLower(key)
		if sanitizeFields[lowerKey] {
			data[key] = "***REDACTED***"
			continue
		}
		if nested, ok := value.(map[string]interface{}); ok {
			sanitizeMap(nested, sanitizeFields)
		}
	}
}
