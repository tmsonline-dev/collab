//! Error types for SuperTokens SDK

use thiserror::Error;

/// Result type for SuperTokens operations
pub type Result<T> = std::result::Result<T, SuperTokensError>;

// / SuperTokens SDK error types
#[derive(Error, Debug, Clone)]
pub enum SuperTokensError {
    /// Network or HTTP request error
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkErrorWrapper),

    /// Invalid credentials provided
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// User not found
    #[error("User not found")]
    UserNotFound,

    /// Email already exists
    #[error("Email already exists")]
    EmailAlreadyExists,

    /// Phone number already exists  
    #[error("Phone number already exists")]
    PhoneNumberAlreadyExists,

    /// Session has expired
    #[error("Session expired")]
    SessionExpired,

    /// Invalid token provided
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Invalid verification code
    #[error("Invalid verification code")]
    InvalidVerificationCode,

    /// Too many attempts
    #[error("Too many attempts")]
    TooManyAttempts,

    /// Account linking error
    #[error("Account linking error: {0}")]
    AccountLinkingError(String),

    /// Multi-factor authentication error
    #[error("MFA error: {0}")]
    MfaError(String),

    /// TOTP error
    #[error("TOTP error: {0}")]
    TotpError(String),

    /// WebAuthn error
    #[error("WebAuthn error: {0}")]
    WebAuthnError(String),

    /// OAuth2 error
    #[error("OAuth2 error: {0}")]
    OAuth2Error(String),

    /// Password policy violation
    #[error("Password policy violation: {0}")]
    PasswordPolicyError(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationErrorWrapper),

    /// Session error
    #[error("Session error: {0}")]
    SessionError(String),

    /// Generic error
    #[error("SuperTokens error: {0}")]
    Generic(String),
}

/// Wrapper for network errors to make them cloneable
#[derive(Error, Debug, Clone)]
#[error("{inner}")]
pub struct NetworkErrorWrapper {
    inner: String,
}

impl From<reqwest::Error> for NetworkErrorWrapper {
    fn from(err: reqwest::Error) -> Self {
        Self {
            inner: err.to_string(),
        }
    }
}

impl From<reqwest::Error> for SuperTokensError {
    fn from(err: reqwest::Error) -> Self {
        SuperTokensError::NetworkError(NetworkErrorWrapper {
            inner: err.to_string(),
        })
    }
}

impl From<serde_json::Error> for SuperTokensError {
    fn from(err: serde_json::Error) -> Self {
        SuperTokensError::SerializationError(err.into())
    }
}

/// Wrapper for serialization errors to make them cloneable
#[derive(Error, Debug, Clone)]
#[error("{inner}")]
pub struct SerializationErrorWrapper {
    inner: String,
}

impl From<serde_json::Error> for SerializationErrorWrapper {
    fn from(err: serde_json::Error) -> Self {
        Self {
            inner: err.to_string(),
        }
    }
}

impl From<url::ParseError> for SuperTokensError {
    fn from(err: url::ParseError) -> Self {
        SuperTokensError::ConfigError(format!("Invalid URL: {}", err))
    }
}

impl SuperTokensError {
    /// Create a new session error
    pub fn session_error(msg: impl Into<String>) -> Self {
        SuperTokensError::SessionError(msg.into())
    }

    /// Create a new configuration error
    pub fn config_error(msg: impl Into<String>) -> Self {
        SuperTokensError::ConfigError(msg.into())
    }

    /// Create a new account linking error
    pub fn account_linking_error(msg: impl Into<String>) -> Self {
        SuperTokensError::AccountLinkingError(msg.into())
    }

    /// Create a new MFA error
    pub fn mfa_error(msg: impl Into<String>) -> Self {
        SuperTokensError::MfaError(msg.into())
    }

    /// Create a new TOTP error
    pub fn totp_error(msg: impl Into<String>) -> Self {
        SuperTokensError::TotpError(msg.into())
    }

    /// Create a new WebAuthn error
    pub fn webauthn_error(msg: impl Into<String>) -> Self {
        SuperTokensError::WebAuthnError(msg.into())
    }

    /// Create a new OAuth2 error
    pub fn oauth2_error(msg: impl Into<String>) -> Self {
        SuperTokensError::OAuth2Error(msg.into())
    }

    /// Create a new password policy error
    pub fn password_policy_error(msg: impl Into<String>) -> Self {
        SuperTokensError::PasswordPolicyError(msg.into())
    }

    /// Create an error from HTTP response
    pub fn from_response(status: u16, body: String) -> Self {
        // Try to parse structured error response
        if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(message) = error_json.get("message").and_then(|m| m.as_str()) {
                return match status {
                    400 => {
                        if message.to_lowercase().contains("password")
                            && message.to_lowercase().contains("policy")
                        {
                            SuperTokensError::PasswordPolicyError(message.to_string())
                        } else if message.to_lowercase().contains("code") {
                            SuperTokensError::InvalidVerificationCode
                        } else {
                            SuperTokensError::Generic(format!("Bad Request: {}", message))
                        }
                    }
                    401 => {
                        if message.to_lowercase().contains("credential") {
                            SuperTokensError::InvalidCredentials
                        } else {
                            SuperTokensError::SessionExpired
                        }
                    }
                    403 => SuperTokensError::Generic(format!("Forbidden: {}", message)),
                    404 => SuperTokensError::UserNotFound,
                    409 => {
                        if message.to_lowercase().contains("email") {
                            SuperTokensError::EmailAlreadyExists
                        } else if message.to_lowercase().contains("phone") {
                            SuperTokensError::PhoneNumberAlreadyExists
                        } else {
                            SuperTokensError::Generic(format!("Conflict: {}", message))
                        }
                    }
                    429 => SuperTokensError::RateLimitExceeded,
                    500..=599 => SuperTokensError::Generic(format!("Server Error: {}", message)),
                    _ => SuperTokensError::Generic(format!("HTTP {}: {}", status, message)),
                };
            }
        }

        // Fallback to status code-based errors
        match status {
            400 => SuperTokensError::Generic("Bad Request".to_string()),
            401 => SuperTokensError::SessionExpired,
            403 => SuperTokensError::Generic("Forbidden".to_string()),
            404 => SuperTokensError::UserNotFound,
            409 => SuperTokensError::EmailAlreadyExists,
            429 => SuperTokensError::RateLimitExceeded,
            500..=599 => SuperTokensError::Generic(format!("Server Error ({})", status)),
            _ => SuperTokensError::Generic(format!("HTTP Error: {} - {}", status, body)),
        }
    }

    /// Check if this error indicates the user should retry
    pub fn is_retryable(&self) -> bool {
        match self {
            SuperTokensError::NetworkError(_) => true,
            SuperTokensError::RateLimitExceeded => true,
            SuperTokensError::Generic(msg) => {
                msg.contains("Server Error")
                    || msg.contains("timeout")
                    || msg.contains("503")
                    || msg.contains("502")
            }
            _ => false,
        }
    }

    /// Check if this error is related to authentication
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            SuperTokensError::InvalidCredentials
                | SuperTokensError::SessionExpired
                | SuperTokensError::InvalidToken(_)
                | SuperTokensError::InvalidVerificationCode
        )
    }

    /// Check if this error is related to user management
    pub fn is_user_error(&self) -> bool {
        matches!(
            self,
            SuperTokensError::UserNotFound
                | SuperTokensError::EmailAlreadyExists
                | SuperTokensError::PhoneNumberAlreadyExists
        )
    }

    /// Check if this error is temporary and might resolve
    pub fn is_temporary(&self) -> bool {
        matches!(
            self,
            SuperTokensError::NetworkError(_)
                | SuperTokensError::RateLimitExceeded
                | SuperTokensError::TooManyAttempts
        )
    }

    /// Get the error code for structured error handling
    pub fn error_code(&self) -> &'static str {
        match self {
            SuperTokensError::NetworkError(_) => "NETWORK_ERROR",
            SuperTokensError::InvalidCredentials => "INVALID_CREDENTIALS",
            SuperTokensError::UserNotFound => "USER_NOT_FOUND",
            SuperTokensError::EmailAlreadyExists => "EMAIL_ALREADY_EXISTS",
            SuperTokensError::PhoneNumberAlreadyExists => "PHONE_NUMBER_ALREADY_EXISTS",
            SuperTokensError::SessionExpired => "SESSION_EXPIRED",
            SuperTokensError::InvalidToken(_) => "INVALID_TOKEN",
            SuperTokensError::InvalidVerificationCode => "INVALID_VERIFICATION_CODE",
            SuperTokensError::TooManyAttempts => "TOO_MANY_ATTEMPTS",
            SuperTokensError::AccountLinkingError(_) => "ACCOUNT_LINKING_ERROR",
            SuperTokensError::MfaError(_) => "MFA_ERROR",
            SuperTokensError::TotpError(_) => "TOTP_ERROR",
            SuperTokensError::WebAuthnError(_) => "WEBAUTHN_ERROR",
            SuperTokensError::OAuth2Error(_) => "OAUTH2_ERROR",
            SuperTokensError::PasswordPolicyError(_) => "PASSWORD_POLICY_ERROR",
            SuperTokensError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            SuperTokensError::ConfigError(_) => "CONFIG_ERROR",
            SuperTokensError::SerializationError(_) => "SERIALIZATION_ERROR",
            SuperTokensError::SessionError(_) => "SESSION_ERROR",
            SuperTokensError::Generic(_) => "GENERIC_ERROR",
        }
    }

    /// Convert error to JSON for API responses
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.error_code(),
            "message": self.to_string()
        })
    }
}

/// Convert SuperTokens errors into HTTP status codes
impl SuperTokensError {
    pub fn to_http_status(&self) -> u16 {
        match self {
            SuperTokensError::InvalidCredentials => 401,
            SuperTokensError::UserNotFound => 404,
            SuperTokensError::EmailAlreadyExists => 409,
            SuperTokensError::PhoneNumberAlreadyExists => 409,
            SuperTokensError::SessionExpired => 401,
            SuperTokensError::InvalidToken(_) => 401,
            SuperTokensError::InvalidVerificationCode => 400,
            SuperTokensError::TooManyAttempts => 429,
            SuperTokensError::PasswordPolicyError(_) => 400,
            SuperTokensError::RateLimitExceeded => 429,
            SuperTokensError::ConfigError(_) => 500,
            SuperTokensError::NetworkError(_) => 503,
            SuperTokensError::SerializationError(_) => 400,
            _ => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = SuperTokensError::InvalidCredentials;
        assert_eq!(error.error_code(), "INVALID_CREDENTIALS");
        assert!(error.is_auth_error());
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_error_categorization() {
        assert!(SuperTokensError::UserNotFound.is_user_error());
        assert!(SuperTokensError::EmailAlreadyExists.is_user_error());
        assert!(SuperTokensError::SessionExpired.is_auth_error());
        assert!(SuperTokensError::RateLimitExceeded.is_temporary());
    }

    #[test]
    fn test_http_status_conversion() {
        assert_eq!(SuperTokensError::InvalidCredentials.to_http_status(), 401);
        assert_eq!(SuperTokensError::UserNotFound.to_http_status(), 404);
        assert_eq!(SuperTokensError::EmailAlreadyExists.to_http_status(), 409);
        assert_eq!(SuperTokensError::RateLimitExceeded.to_http_status(), 429);
    }

    #[test]
    fn test_json_serialization() {
        let error = SuperTokensError::InvalidCredentials;
        let json = error.to_json();

        assert_eq!(json["error"], "INVALID_CREDENTIALS");
        assert_eq!(json["message"], "Invalid credentials");
    }

    #[test]
    fn test_from_response() {
        let error = SuperTokensError::from_response(
            401,
            r#"{"message": "Invalid credentials"}"#.to_string(),
        );
        assert!(matches!(error, SuperTokensError::InvalidCredentials));

        let error = SuperTokensError::from_response(
            409,
            r#"{"message": "Email already exists"}"#.to_string(),
        );
        assert!(matches!(error, SuperTokensError::EmailAlreadyExists));
    }
}
