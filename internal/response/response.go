package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	ErrCodeInvalidInput       = "INVALID_INPUT"
	ErrCodeInvalidCredentials = "INVALID_CREDENTIALS"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeEmailExists        = "EMAIL_ALREADY_EXISTS"
	ErrCodeInvalidToken       = "INVALID_TOKEN"
	ErrCodeTooManyRequests    = "TOO_MANY_REQUESTS"
	ErrCodeInternalError      = "INTERNAL_ERROR"
	ErrCodeEmailNotVerified   = "EMAIL_NOT_VERIFIED"
	ErrCodeForbidden          = "FORBIDDEN"
)

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type APIResponse struct {
	Success bool         `json:"success"`
	Data    interface{}  `json:"data,omitempty"`
	Error   *ErrorDetail `json:"error,omitempty"`
}

func RespondOK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

func RespondCreated(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Data:    data,
	})
}

func RespondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, APIResponse{
		Success: false,
		Error: &ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}
