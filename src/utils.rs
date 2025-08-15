//! Utility functions for the SuperTokens SDK

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::Client;
use std::collections::HashMap;
use url::Url;

/// HTTP client creation with common configuration
pub fn create_http_client(config: &SuperTokensConfig) -> Result<Client> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.options.timeout_seconds,
        ))
        .user_agent(format!("SuperTokens-Rust-SDK/{}", crate::VERSION))
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            );
            if let Some(api_key) = &config.api_key {
                headers.insert(
                    "api-key",
                    reqwest::header::HeaderValue::from_str(api_key).map_err(|_| {
                        SuperTokensError::Generic("Invalid API key format".to_string())
                    })?,
                );
            }
            headers
        })
        .build()?;
    Ok(client)
}

/// Validate email format
pub fn is_valid_email(email: &str) -> bool {
    let email_regex = regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    email_regex.is_match(email)
}

/// Validate phone number format (basic validation)
pub fn is_valid_phone_number(phone: &str) -> bool {
    let phone_regex = regex::Regex::new(r"^\+?[1-9]\d{1,14}$").unwrap();
    phone_regex.is_match(phone)
}

/// Generate a secure random string
pub fn generate_random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Base64 URL-safe encode
pub fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64 URL-safe decode
pub fn base64_url_decode(data: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| SuperTokensError::Generic(format!("Base64 decode error: {}", e)))
}

/// Convert timestamp to DateTime
pub fn timestamp_to_datetime(timestamp: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(timestamp / 1000, ((timestamp % 1000) * 1_000_000) as u32)
        .unwrap_or_else(|| Utc::now())
}

/// Convert DateTime to timestamp
pub fn datetime_to_timestamp(datetime: DateTime<Utc>) -> i64 {
    datetime.timestamp() * 1000 + datetime.timestamp_subsec_millis() as i64
}

/// Merge two JSON objects
pub fn merge_json_objects(base: &mut serde_json::Value, overlay: serde_json::Value) -> Result<()> {
    if let (serde_json::Value::Object(base_map), serde_json::Value::Object(overlay_map)) =
        (base, overlay)
    {
        for (key, value) in overlay_map {
            base_map.insert(key, value);
        }
        Ok(())
    } else {
        Err(SuperTokensError::Generic(
            "Cannot merge non-object JSON values".to_string(),
        ))
    }
}

/// Sanitize user input to prevent injection attacks
pub fn sanitize_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || " -_@.+".contains(*c))
        .take(255) // Limit length
        .collect()
}

/// Extract domain from email
pub fn extract_domain_from_email(email: &str) -> Option<String> {
    email.split('@').nth(1).map(|s| s.to_lowercase())
}

/// Validate URL format
pub fn is_valid_url(url_str: &str) -> bool {
    Url::parse(url_str).is_ok()
}

/// Create query string from parameters
pub fn build_query_string(params: &HashMap<String, String>) -> String {
    if params.is_empty() {
        return String::new();
    }

    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!("?{}", query)
}

/// Parse query string into HashMap
pub fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();

    for pair in query.trim_start_matches('?').split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if let (Ok(key), Ok(value)) = (urlencoding::decode(key), urlencoding::decode(value)) {
                params.insert(key.to_string(), value.to_string());
            }
        }
    }

    params
}

/// Hash password using PBKDF2 (for client-side hashing if needed)
pub fn hash_password(password: &str, salt: &str) -> Result<String> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut result = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), 100_000, &mut result);

    Ok(base64_url_encode(&result))
}

/// Generate salt for password hashing
pub fn generate_salt() -> String {
    generate_random_string(32)
}

/// Create PKCE (Proof Key for Code Exchange) challenge and verifier
pub fn create_pkce_challenge() -> Result<(String, String)> {
    use sha2::{Digest, Sha256};

    // Generate code verifier (43-128 characters)
    let code_verifier = generate_random_string(128);

    // Create code challenge (SHA256 hash of verifier, base64url encoded)
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let code_challenge = base64_url_encode(&hash);

    Ok((code_verifier, code_challenge))
}

/// Extract JWT header without verification
pub fn extract_jwt_header(jwt: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(SuperTokensError::InvalidToken(
            "Invalid JWT format".to_string(),
        ));
    }

    let header_bytes = base64_url_decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| SuperTokensError::InvalidToken(format!("Invalid JWT header: {}", e)))?;

    Ok(header)
}

/// Extract JWT payload without verification
pub fn extract_jwt_payload(jwt: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(SuperTokensError::InvalidToken(
            "Invalid JWT format".to_string(),
        ));
    }

    let payload_bytes = base64_url_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SuperTokensError::InvalidToken(format!("Invalid JWT payload: {}", e)))?;

    Ok(payload)
}

/// Check if JWT is expired (without signature verification)
pub fn is_jwt_expired_unsafe(jwt: &str) -> Result<bool> {
    let payload = extract_jwt_payload(jwt)?;

    if let Some(exp) = payload.get("exp").and_then(|e| e.as_i64()) {
        let now = chrono::Utc::now().timestamp();
        Ok(now >= exp)
    } else {
        Ok(false) // No expiration claim
    }
}

/// Mask sensitive data for logging
pub fn mask_sensitive_data(data: &str, show_chars: usize) -> String {
    if data.len() <= show_chars * 2 {
        "*".repeat(data.len())
    } else {
        let start = &data[..show_chars];
        let end = &data[data.len() - show_chars..];
        format!("{}***{}", start, end)
    }
}

/// Log request/response for debugging (with sensitive data masking)
pub fn log_http_request(method: &str, url: &str, headers: &reqwest::header::HeaderMap) {
    log::debug!("HTTP Request: {} {}", method, url);

    for (name, value) in headers.iter() {
        let header_name = name.as_str();
        let header_value = if header_name.to_lowercase().contains("authorization")
            || header_name.to_lowercase().contains("api-key")
            || header_name.to_lowercase().contains("cookie")
        {
            mask_sensitive_data(value.to_str().unwrap_or(""), 4)
        } else {
            value.to_str().unwrap_or("").to_string()
        };

        log::debug!("  {}: {}", header_name, header_value);
    }
}

/// Retry HTTP request with exponential backoff
pub async fn retry_request<F, Fut, T>(
    operation: F,
    max_retries: u32,
    base_delay_ms: u64,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..=max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);

                if attempt < max_retries {
                    let delay = base_delay_ms * 2_u64.pow(attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }

    Err(last_error.unwrap())
}

/// Convert SuperTokens error response to structured error
pub fn parse_error_response(status: u16, body: &str) -> SuperTokensError {
    // Try to parse as JSON error response
    if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(message) = error_json.get("message").and_then(|m| m.as_str()) {
            return match status {
                400 => SuperTokensError::Generic(format!("Bad Request: {}", message)),
                401 => SuperTokensError::SessionExpired,
                403 => SuperTokensError::Generic(format!("Forbidden: {}", message)),
                404 => SuperTokensError::UserNotFound,
                409 => {
                    if message.to_lowercase().contains("email") {
                        SuperTokensError::EmailAlreadyExists
                    } else {
                        SuperTokensError::Generic(format!("Conflict: {}", message))
                    }
                }
                429 => SuperTokensError::Generic("Rate limit exceeded".to_string()),
                500..=599 => SuperTokensError::Generic(format!("Server Error: {}", message)),
                _ => SuperTokensError::Generic(format!("HTTP {}: {}", status, message)),
            };
        }
    }

    // Fallback to status-based errors
    match status {
        400 => SuperTokensError::Generic("Bad Request".to_string()),
        401 => SuperTokensError::SessionExpired,
        403 => SuperTokensError::Generic("Forbidden".to_string()),
        404 => SuperTokensError::UserNotFound,
        409 => SuperTokensError::EmailAlreadyExists,
        429 => SuperTokensError::Generic("Rate limit exceeded".to_string()),
        500..=599 => SuperTokensError::Generic(format!("Server Error ({})", status)),
        _ => SuperTokensError::Generic(format!("HTTP Error: {}", status)),
    }
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(SuperTokensError::Generic(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;':\",./<>?".contains(c));

    if !has_upper || !has_lower || !has_digit || !has_special {
        return Err(SuperTokensError::Generic(
            "Password must contain uppercase, lowercase, digit, and special character".to_string(),
        ));
    }

    Ok(())
}

/// Create a normalized user identifier for account linking
pub fn create_user_identifier(
    email: Option<&str>,
    phone: Option<&str>,
    third_party_id: Option<&str>,
    third_party_user_id: Option<&str>,
) -> String {
    if let Some(email) = email {
        format!("email:{}", email.to_lowercase())
    } else if let Some(phone) = phone {
        format!("phone:{}", phone)
    } else if let (Some(provider), Some(user_id)) = (third_party_id, third_party_user_id) {
        format!("third_party:{}:{}", provider, user_id)
    } else {
        format!("unknown:{}", uuid::Uuid::new_v4())
    }
}

/// Extract tenant ID from request or use default
pub fn extract_tenant_id(tenant_id: Option<&str>) -> String {
    tenant_id.unwrap_or("public").to_string()
}

/// Format duration for human readability
pub fn format_duration(seconds: u64) -> String {
    match seconds {
        s if s < 60 => format!("{}s", s),
        s if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        s if s < 86400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d {}h", s / 86400, (s % 86400) / 3600),
    }
}

/// Configuration validation helpers
pub mod config_validation {
    use super::*;

    pub fn validate_api_domain(domain: &str) -> Result<()> {
        if !is_valid_url(domain) {
            return Err(SuperTokensError::Generic(
                "Invalid API domain URL".to_string(),
            ));
        }

        let url = Url::parse(domain)?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(SuperTokensError::Generic(
                "API domain must use HTTP or HTTPS".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_app_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(SuperTokensError::Generic(
                "App name cannot be empty".to_string(),
            ));
        }

        if name.len() > 100 {
            return Err(SuperTokensError::Generic(
                "App name too long (max 100 characters)".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_website_domain(domain: &str) -> Result<()> {
        if !is_valid_url(domain) {
            return Err(SuperTokensError::Generic(
                "Invalid website domain URL".to_string(),
            ));
        }

        Ok(())
    }
}

/// Testing utilities
#[cfg(test)]
pub mod test_utils {
    use super::*;

    pub fn create_test_config() -> SuperTokensConfig {
        SuperTokensConfig::new("http://localhost:3567", "TestApp", "http://localhost:3000")
    }

    pub fn generate_test_email() -> String {
        format!("test-{}@example.com", generate_random_string(8))
    }

    pub fn generate_test_user_id() -> String {
        format!("user-{}", uuid::Uuid::new_v4())
    }

    pub async fn wait_for_eventual_consistency() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

// Add required dependencies to Cargo.toml
/*
[dependencies]
regex = "1.0"
rand = "0.8"
pbkdf2 = "0.12"
sha2 = "0.10"
urlencoding = "2.1"
log = "0.4"
*/
