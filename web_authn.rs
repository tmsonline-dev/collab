//! WebAuthn authentication recipe

use crate::{config::SuperTokensConfig, errors::SuperTokensError, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WebAuthn credential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub id: String,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u32,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub transports: Vec<AuthenticatorTransport>,
}

/// Authenticator attachment type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

/// Authenticator transport methods
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    Internal,
    Hybrid,
}

/// WebAuthn registration options
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: UserEntity,
    #[serde(rename = "pubKeyCredParams")]
    pub public_key_credential_params: Vec<PublicKeyCredentialParameters>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub attestation: AttestationConveyancePreference,
}

/// Relying party information
#[derive(Debug, Serialize, Deserialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// User entity for WebAuthn
#[derive(Debug, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i32,
}

/// Authenticator selection criteria
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: bool,
    #[serde(rename = "residentKey")]
    pub resident_key: ResidentKeyRequirement,
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,
}

/// Resident key requirement
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    Discouraged,
    Preferred,
    Required,
}

/// User verification requirement
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

/// Public key credential descriptor
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// Attestation conveyance preference
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

/// WebAuthn authentication options
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    pub challenge: String,
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,
}

/// Request for WebAuthn registration options
#[derive(Serialize)]
struct RegistrationOptionsRequest {
    #[serde(rename = "userId")]
    user_id: String,
    email: String,
}

/// Response for WebAuthn registration options
#[derive(Deserialize)]
struct RegistrationOptionsResponse {
    status: String,
    #[serde(rename = "publicKeyCredentialCreationOptions")]
    options: Option<RegistrationOptions>,
}

/// Request for completing WebAuthn registration
#[derive(Serialize)]
struct CompleteRegistrationRequest {
    #[serde(rename = "userId")]
    user_id: String,
    credential: PublicKeyCredentialAttestation,
}

/// Public key credential with attestation
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialAttestation {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Authenticator attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Response for completing WebAuthn registration
#[derive(Deserialize)]
struct CompleteRegistrationResponse {
    status: String,
    credential: Option<WebAuthnCredential>,
}

/// Request for WebAuthn authentication options
#[derive(Serialize)]
struct AuthenticationOptionsRequest {
    email: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

/// Response for WebAuthn authentication options
#[derive(Deserialize)]
struct AuthenticationOptionsResponse {
    status: String,
    #[serde(rename = "publicKeyCredentialRequestOptions")]
    options: Option<AuthenticationOptions>,
}

/// Request for completing WebAuthn authentication
#[derive(Serialize)]
struct CompleteAuthenticationRequest {
    credential: PublicKeyCredentialAssertion,
}

/// Public key credential assertion
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialAssertion {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Authenticator assertion response
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// Response for completing WebAuthn authentication
#[derive(Deserialize)]
struct CompleteAuthenticationResponse {
    status: String,
    user: Option<WebAuthnUser>,
}

/// WebAuthn user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnUser {
    pub id: String,
    pub email: String,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub time_joined: DateTime<Utc>,
}

/// Get WebAuthn registration options for a user
pub async fn get_registration_options(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    email: impl Into<String>,
) -> Result<RegistrationOptions> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/registration/options", config.api_domain);
    
    let request_body = RegistrationOptionsRequest {
        user_id: user_id.into(),
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
    
    let options_response: RegistrationOptionsResponse = response.json().await?;
    
    match options_response.status.as_str() {
        "OK" => options_response.options.ok_or_else(|| {
            SuperTokensError::webauthn_error("Registration options succeeded but no options returned")
        }),
        _ => Err(SuperTokensError::webauthn_error(format!(
            "Unknown registration options status: {}",
            options_response.status
        ))),
    }
}

/// Complete WebAuthn registration
pub async fn complete_registration(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    credential: PublicKeyCredentialAttestation,
) -> Result<WebAuthnCredential> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/registration/verify", config.api_domain);
    
    let request_body = CompleteRegistrationRequest {
        user_id: user_id.into(),
        credential,
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
    
    let registration_response: CompleteRegistrationResponse = response.json().await?;
    
    match registration_response.status.as_str() {
        "OK" => registration_response.credential.ok_or_else(|| {
            SuperTokensError::webauthn_error("Registration completed but no credential returned")
        }),
        "INVALID_CREDENTIAL_ERROR" => Err(SuperTokensError::webauthn_error(
            "Invalid WebAuthn credential"
        )),
        _ => Err(SuperTokensError::webauthn_error(format!(
            "Unknown registration completion status: {}",
            registration_response.status
        ))),
    }
}

/// Get WebAuthn authentication options
pub async fn get_authentication_options(
    config: &SuperTokensConfig,
    email: Option<String>,
    user_id: Option<String>,
) -> Result<AuthenticationOptions> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/authentication/options", config.api_domain);
    
    let request_body = AuthenticationOptionsRequest { email, user_id };
    
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
    
    let options_response: AuthenticationOptionsResponse = response.json().await?;
    
    match options_response.status.as_str() {
        "OK" => options_response.options.ok_or_else(|| {
            SuperTokensError::webauthn_error("Authentication options succeeded but no options returned")
        }),
        _ => Err(SuperTokensError::webauthn_error(format!(
            "Unknown authentication options status: {}",
            options_response.status
        ))),
    }
}

/// Complete WebAuthn authentication
pub async fn complete_authentication(
    config: &SuperTokensConfig,
    credential: PublicKeyCredentialAssertion,
) -> Result<WebAuthnUser> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/authentication/verify", config.api_domain);
    
    let request_body = CompleteAuthenticationRequest { credential };
    
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
    
    let auth_response: CompleteAuthenticationResponse = response.json().await?;
    
    match auth_response.status.as_str() {
        "OK" => auth_response.user.ok_or_else(|| {
            SuperTokensError::webauthn_error("Authentication completed but no user returned")
        }),
        "INVALID_CREDENTIAL_ERROR" => Err(SuperTokensError::webauthn_error(
            "Invalid WebAuthn credential"
        )),
        "CREDENTIAL_NOT_FOUND_ERROR" => Err(SuperTokensError::webauthn_error(
            "WebAuthn credential not found"
        )),
        _ => Err(SuperTokensError::webauthn_error(format!(
            "Unknown authentication completion status: {}",
            auth_response.status
        ))),
    }
}

/// Get all WebAuthn credentials for a user
pub async fn get_user_credentials(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Vec<WebAuthnCredential>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/credentials", config.api_domain);
    
    let mut request = client.get(&url).query(&[("userId", user_id.into())]);
    
    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }
    
    let response = request.send().await?;
    
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }
    
    let credentials: Vec<WebAuthnCredential> = response.json().await?;
    Ok(credentials)
}

/// Remove a WebAuthn credential
pub async fn remove_credential(
    config: &SuperTokensConfig,
    credential_id: impl Into<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/credential", config.api_domain);
    
    let mut request = client.delete(&url).query(&[("credentialId", credential_id.into())]);
    
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
//! Additional WebAuthn functions missing from your current implementation

// Add these functions to your webauthn.rs file:

/// Check if an email exists in the system (for WebAuthn flows)
pub async fn does_email_exist(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    email: impl Into<String>,
) -> Result<bool> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/email/exists", config.api_domain);
    
    let tenant_id = tenant_id.unwrap_or_else(|| "public".to_string());
    let mut request = client.get(&url)
        .query(&[("email", email.into()), ("tenantId", tenant_id)]);
    
    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }
    
    let response = request.send().await?;
    
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }
    
    let exists_response: serde_json::Value = response.json().await?;
    
    match exists_response.get("status").and_then(|s| s.as_str()) {
        Some("OK") => Ok(exists_response.get("exists")
            .and_then(|e| e.as_bool())
            .unwrap_or(false)),
        _ => Err(SuperTokensError::webauthn_error("Unknown email exists status")),
    }
}

/// WebAuthn sign up flow
pub async fn sign_up(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    email: impl Into<String>,
    credential: PublicKeyCredentialAttestation,
) -> Result<(WebAuthnUser, bool)> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/signup", config.api_domain);
    
    let request_body = serde_json::json!({
        "tenantId": tenant_id.unwrap_or_else(|| "public".to_string()),
        "email": email.into(),
        "credential": credential
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
    
    let signup_response: serde_json::Value = response.json().await?;
    
    match signup_response.get("status").and_then(|s| s.as_str()) {
        Some("OK") => {
            let user: WebAuthnUser = serde_json::from_value(
                signup_response.get("user").unwrap().clone()
            )?;
            let created_new_user = signup_response.get("createdNewUser")
                .and_then(|c| c.as_bool())
                .unwrap_or(false);
            Ok((user, created_new_user))
        }
        Some("EMAIL_ALREADY_EXISTS_ERROR") => Err(SuperTokensError::EmailAlreadyExists),
        _ => Err(SuperTokensError::webauthn_error("Unknown signup status")),
    }
}

/// WebAuthn sign in flow
pub async fn sign_in(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    credential: PublicKeyCredentialAssertion,
) -> Result<WebAuthnUser> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/signin", config.api_domain);
    
    let request_body = serde_json::json!({
        "tenantId": tenant_id.unwrap_or_else(|| "public".to_string()),
        "credential": credential
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
    
    let signin_response: serde_json::Value = response.json().await?;
    
    match signin_response.get("status").and_then(|s| s.as_str()) {
        Some("OK") => {
            let user: WebAuthnUser = serde_json::from_value(
                signin_response.get("user").unwrap().clone()
            )?;
            Ok(user)
        }
        Some("WRONG_CREDENTIALS_ERROR") => Err(SuperTokensError::InvalidCredentials),
        _ => Err(SuperTokensError::webauthn_error("Unknown signin status")),
    }
}

/// Get WebAuthn user by ID
pub async fn get_user_by_id(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Option<WebAuthnUser>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/user", config.api_domain);
    
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
    
    let user: WebAuthnUser = response.json().await?;
    Ok(Some(user))
}

/// Get WebAuthn user by email
pub async fn get_user_by_email(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    email: impl Into<String>,
) -> Result<Option<WebAuthnUser>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/user/email", config.api_domain);
    
    let tenant_id = tenant_id.unwrap_or_else(|| "public".to_string());
    let mut request = client.get(&url)
        .query(&[("email", email.into()), ("tenantId", tenant_id)]);
    
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
    
    let user: WebAuthnUser = response.json().await?;
    Ok(Some(user))
}

/// Create password reset token for WebAuthn user
pub async fn create_reset_password_token(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    user_id: impl Into<String>,
) -> Result<String> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/user/reset/token", config.api_domain);
    
    let request_body = serde_json::json!({
        "tenantId": tenant_id.unwrap_or_else(|| "public".to_string()),
        "userId": user_id.into()
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
    
    let token_response: serde_json::Value = response.json().await?;
    
    match token_response.get("status").and_then(|s| s.as_str()) {
        Some("OK") => Ok(token_response.get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| SuperTokensError::webauthn_error("No token in response"))?
            .to_string()),
        Some("UNKNOWN_USER_ID_ERROR") => Err(SuperTokensError::UserNotFound),
        _ => Err(SuperTokensError::webauthn_error("Unknown reset token status")),
    }
}

/// Reset WebAuthn account using token
pub async fn reset_password_using_token(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    token: impl Into<String>,
    new_credential: PublicKeyCredentialAttestation,
) -> Result<String> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/user/reset", config.api_domain);
    
    let request_body = serde_json::json!({
        "tenantId": tenant_id.unwrap_or_else(|| "public".to_string()),
        "token": token.into(),
        "newCredential": new_credential
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
    
    let reset_response: serde_json::Value = response.json().await?;
    
    match reset_response.get("status").and_then(|s| s.as_str()) {
        Some("OK") => Ok(reset_response.get("userId")
            .and_then(|u| u.as_str())
            .ok_or_else(|| SuperTokensError::webauthn_error("No user ID in response"))?
            .to_string()),
        Some("RESET_PASSWORD_INVALID_TOKEN_ERROR") => Err(SuperTokensError::InvalidToken(
            "Invalid reset password token".to_string()
        )),
        _ => Err(SuperTokensError::webauthn_error("Unknown reset password status")),
    }
}

/// Create password reset link for WebAuthn user
pub async fn create_reset_password_link(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    user_id: impl Into<String>,
) -> Result<String> {
    let token = create_reset_password_token(config, tenant_id.clone(), user_id).await?;
    let tenant_id = tenant_id.unwrap_or_else(|| "public".to_string());
    
    Ok(format!(
        "{}/auth/reset-password?token={}&tenantId={}",
        config.website_domain, token, tenant_id
    ))
}

/// Check if two WebAuthn credential infos are the same (for account linking)
pub fn has_same_webauthn_info_as(
    credential1: &WebAuthnCredential,
    credential2: &WebAuthnCredential,
) -> bool {
    credential1.credential_id == credential2.credential_id
}

/// List users by WebAuthn credential ID (for account linking)
pub async fn list_users_by_credential_id(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    credential_id: impl Into<String>,
) -> Result<Vec<WebAuthnUser>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/webauthn/users", config.api_domain);
    
    let tenant_id = tenant_id.unwrap_or_else(|| "public".to_string());
    let mut request = client.get(&url)
        .query(&[("credentialId", credential_id.into()), ("tenantId", tenant_id)]);
    
    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }
    
    let response = request.send().await?;
    
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }
    
    let users: Vec<WebAuthnUser> = response.json().await?;
    Ok(users)
}

/// Create HTTP client with timeout
fn create_http_client(config: &SuperTokensConfig) -> Result<Client> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.options.timeout_seconds))
        .build()?;
    Ok(client)
}