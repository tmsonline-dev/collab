//! Email verification recipe

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Email verification mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EmailVerificationMode {
    Required,
    Optional,
}

/// Email verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationStatus {
    pub is_verified: bool,
    pub email: String,
}

/// Request to create email verification token
#[derive(Serialize)]
struct CreateEmailVerificationTokenRequest {
    #[serde(rename = "recipeUserId")]
    recipe_user_id: String,
    email: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

/// Response from creating email verification token
#[derive(Deserialize)]
struct CreateEmailVerificationTokenResponse {
    status: String,
    token: Option<String>,
}

/// Request to verify email using token
#[derive(Serialize)]
struct VerifyEmailUsingTokenRequest {
    token: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

/// Response from verifying email using token
#[derive(Deserialize)]
struct VerifyEmailUsingTokenResponse {
    status: String,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    email: Option<String>,
}

/// Request to create email verification link
#[derive(Serialize)]
struct CreateEmailVerificationLinkRequest {
    #[serde(rename = "recipeUserId")]
    recipe_user_id: String,
    email: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

/// Response from creating email verification link
#[derive(Deserialize)]
struct CreateEmailVerificationLinkResponse {
    status: String,
    link: Option<String>,
}

/// Response for checking if email is verified
#[derive(Deserialize)]
struct IsEmailVerifiedResponse {
    status: String,
    #[serde(rename = "isVerified")]
    is_verified: Option<bool>,
}

/// Create an email verification token
pub async fn create_email_verification_token(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    recipe_user_id: impl Into<String>,
    email: impl Into<String>,
) -> Result<String> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/email/verify/token", config.api_domain);

    let request_body = CreateEmailVerificationTokenRequest {
        recipe_user_id: recipe_user_id.into(),
        email: email.into(),
        tenant_id: tenant_id.into(),
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

    let token_response: CreateEmailVerificationTokenResponse = response.json().await?;

    match token_response.status.as_str() {
        "OK" => token_response.token.ok_or_else(|| {
            SuperTokensError::Generic(
                "Email verification token creation succeeded but no token returned".to_string(),
            )
        }),
        "EMAIL_ALREADY_VERIFIED_ERROR" => Err(SuperTokensError::Generic(
            "Email is already verified".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown create email verification token status: {}",
            token_response.status
        ))),
    }
}

/// Verify email using a verification token
pub async fn verify_email_using_token(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    token: impl Into<String>,
) -> Result<(String, String)> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/email/verify", config.api_domain);

    let request_body = VerifyEmailUsingTokenRequest {
        token: token.into(),
        tenant_id: tenant_id.into(),
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

    let verify_response: VerifyEmailUsingTokenResponse = response.json().await?;

    match verify_response.status.as_str() {
        "OK" => {
            let user_id = verify_response.user_id.ok_or_else(|| {
                SuperTokensError::Generic(
                    "Email verification succeeded but no user ID returned".to_string(),
                )
            })?;
            let email = verify_response.email.ok_or_else(|| {
                SuperTokensError::Generic(
                    "Email verification succeeded but no email returned".to_string(),
                )
            })?;
            Ok((user_id, email))
        }
        "EMAIL_VERIFICATION_INVALID_TOKEN_ERROR" => Err(SuperTokensError::InvalidToken(
            "Email verification token is invalid or expired".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown verify email status: {}",
            verify_response.status
        ))),
    }
}

/// Create an email verification link
pub async fn create_email_verification_link(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    recipe_user_id: impl Into<String>,
    email: impl Into<String>,
) -> Result<String> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/email/verify/link", config.api_domain);

    let request_body = CreateEmailVerificationLinkRequest {
        recipe_user_id: recipe_user_id.into(),
        email: email.into(),
        tenant_id: tenant_id.into(),
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

    let link_response: CreateEmailVerificationLinkResponse = response.json().await?;

    match link_response.status.as_str() {
        "OK" => link_response.link.ok_or_else(|| {
            SuperTokensError::Generic(
                "Email verification link creation succeeded but no link returned".to_string(),
            )
        }),
        "EMAIL_ALREADY_VERIFIED_ERROR" => Err(SuperTokensError::Generic(
            "Email is already verified".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown create email verification link status: {}",
            link_response.status
        ))),
    }
}

/// Check if an email is verified
pub async fn is_email_verified(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
    email: impl Into<String>,
) -> Result<bool> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/email/verify", config.api_domain);

    let mut request = client.get(&url).query(&[
        ("recipeUserId", recipe_user_id.into()),
        ("email", email.into()),
    ]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let verify_response: IsEmailVerifiedResponse = response.json().await?;

    match verify_response.status.as_str() {
        "OK" => Ok(verify_response.is_verified.unwrap_or(false)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown is email verified status: {}",
            verify_response.status
        ))),
    }
}

/// Manually mark an email as unverified
pub async fn unverify_email(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
    email: impl Into<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/email/verify/remove", config.api_domain);

    let request_body = serde_json::json!({
        "recipeUserId": recipe_user_id.into(),
        "email": email.into()
    });

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

    Ok(())
}

/// Resend email verification email
pub async fn send_email_verification_email(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    user_id: impl Into<String>,
    email: impl Into<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/email/verify", config.api_domain);

    let request_body = serde_json::json!({
        "tenantId": tenant_id.into(),
        "userId": user_id.into(),
        "email": email.into()
    });

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

    Ok(())
}

/// Create HTTP client with timeout
fn create_http_client(config: &SuperTokensConfig) -> Result<Client> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.options.timeout_seconds,
        ))
        .build()?;
    Ok(client)
}
