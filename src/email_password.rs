//! Email/Password authentication recipe

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User information from email/password sign up or sign in
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailPasswordUser {
    pub id: String,
    pub email: String,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub time_joined: DateTime<Utc>,
}

/// Request for email/password sign up
#[derive(Serialize)]
struct SignUpRequest {
    email: String,
    password: String,
}

/// Response from email/password sign up
#[derive(Deserialize)]
struct SignUpResponse {
    status: String,
    user: Option<EmailPasswordUser>,
}

/// Request for email/password sign in
#[derive(Serialize)]
struct SignInRequest {
    email: String,
    password: String,
}

/// Response from email/password sign in
#[derive(Deserialize)]
struct SignInResponse {
    status: String,
    user: Option<EmailPasswordUser>,
}

/// Request for password reset
#[derive(Serialize)]
struct ResetPasswordRequest {
    method: String,
    email: String,
}

/// Response from password reset request
#[derive(Deserialize)]
struct ResetPasswordResponse {
    status: String,
}

/// Request for password reset verification
#[derive(Serialize)]
struct ResetPasswordVerifyRequest {
    method: String,
    token: String,
    #[serde(rename = "newPassword")]
    new_password: String,
}

/// Response from password reset verification
#[derive(Deserialize)]
struct ResetPasswordVerifyResponse {
    status: String,
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

/// Sign up a new user with email and password
pub async fn sign_up(
    config: &SuperTokensConfig,
    email: impl Into<String>,
    password: impl Into<String>,
) -> Result<EmailPasswordUser> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/signup", config.api_domain);

    let request_body = SignUpRequest {
        email: email.into(),
        password: password.into(),
    };

    let mut request = client.post(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let signup_response: SignUpResponse = response.json().await?;

    match signup_response.status.as_str() {
        "OK" => signup_response.user.ok_or_else(|| {
            SuperTokensError::Generic("Sign up succeeded but no user returned".to_string())
        }),
        "EMAIL_ALREADY_EXISTS_ERROR" => Err(SuperTokensError::EmailAlreadyExists),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown sign up status: {}",
            signup_response.status
        ))),
    }
}

/// Sign in an existing user with email and password
pub async fn sign_in(
    config: &SuperTokensConfig,
    email: impl Into<String>,
    password: impl Into<String>,
) -> Result<EmailPasswordUser> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/signin", config.api_domain);

    let request_body = SignInRequest {
        email: email.into(),
        password: password.into(),
    };

    let mut request = client.post(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let signin_response: SignInResponse = response.json().await?;

    match signin_response.status.as_str() {
        "OK" => signin_response.user.ok_or_else(|| {
            SuperTokensError::Generic("Sign in succeeded but no user returned".to_string())
        }),
        "WRONG_CREDENTIALS_ERROR" => Err(SuperTokensError::InvalidCredentials),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown sign in status: {}",
            signin_response.status
        ))),
    }
}

/// Request a password reset for a user
pub async fn request_password_reset(
    config: &SuperTokensConfig,
    email: impl Into<String>,
) -> Result<()> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/user/password/reset/token", config.api_domain);

    let request_body = ResetPasswordRequest {
        method: "email".to_string(),
        email: email.into(),
    };

    let mut request = client.post(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let reset_response: ResetPasswordResponse = response.json().await?;

    match reset_response.status.as_str() {
        "OK" => Ok(()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown password reset status: {}",
            reset_response.status
        ))),
    }
}

/// Reset password using a token received via email
pub async fn reset_password_with_token(
    config: &SuperTokensConfig,
    token: impl Into<String>,
    new_password: impl Into<String>,
) -> Result<String> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/user/password/reset", config.api_domain);

    let request_body = ResetPasswordVerifyRequest {
        method: "token".to_string(),
        token: token.into(),
        new_password: new_password.into(),
    };

    let mut request = client.post(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let verify_response: ResetPasswordVerifyResponse = response.json().await?;

    match verify_response.status.as_str() {
        "OK" => verify_response.user_id.ok_or_else(|| {
            SuperTokensError::Generic(
                "Password reset succeeded but no user ID returned".to_string(),
            )
        }),
        "RESET_PASSWORD_INVALID_TOKEN_ERROR" => Err(SuperTokensError::InvalidToken(
            "Password reset token is invalid or expired".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown password reset verification status: {}",
            verify_response.status
        ))),
    }
}

/// Get user by email
pub async fn get_user_by_email(
    config: &SuperTokensConfig,
    email: impl Into<String>,
) -> Result<Option<EmailPasswordUser>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/user", config.api_domain);

    let mut request = client.get(&url).query(&[("email", email.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let user: EmailPasswordUser = response.json().await?;
    Ok(Some(user))
}

/// Get user by ID
pub async fn get_user_by_id(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Option<EmailPasswordUser>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/user", config.api_domain);

    let mut request = client.get(&url).query(&[("userId", user_id.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let user: EmailPasswordUser = response.json().await?;
    Ok(Some(user))
}

/// Update user email
pub async fn update_user_email(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    new_email: impl Into<String>,
) -> Result<()> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/user", config.api_domain);

    let request_body = serde_json::json!({
        "userId": user_id.into(),
        "email": new_email.into()
    });

    let mut request = client.put(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();

        return Err(match status {
            409 => SuperTokensError::EmailAlreadyExists,
            404 => SuperTokensError::UserNotFound,
            _ => SuperTokensError::from_response(status, error_text),
        });
    }

    Ok(())
}
