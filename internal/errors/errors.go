package errors

import "fmt"

// AppError represents a custom application error
type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	Err     error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// Predefined error types
var (
	ErrDatabaseConnection = &AppError{Code: "DB_CONNECTION_FAILED", Message: "Failed to connect to database"}
	ErrKubernetesClient   = &AppError{Code: "K8S_CLIENT_FAILED", Message: "Failed to initialize Kubernetes client"}
	ErrDERPClient         = &AppError{Code: "DERP_CLIENT_FAILED", Message: "Failed to initialize DERP client"}
	ErrInvalidCredentials = &AppError{Code: "INVALID_CREDENTIALS", Message: "Invalid credentials"}
	ErrAccountLocked      = &AppError{Code: "ACCOUNT_LOCKED", Message: "Account is locked"}
	ErrUnauthorized       = &AppError{Code: "UNAUTHORIZED", Message: "Unauthorized access"}
	ErrValidationFailed   = &AppError{Code: "VALIDATION_FAILED", Message: "Validation failed"}
)

// New creates a new AppError
func New(code, message string) *AppError {
	return &AppError{Code: code, Message: message}
}

// Wrap wraps an error with additional context
func Wrap(err error, code, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

