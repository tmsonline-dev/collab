//! Multi-Factor Authentication (MFA) recipe

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MFA factor types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum FactorId {
    #[serde(rename = "emailpassword")]
    EmailPassword,
    #[serde(rename = "thirdparty")]
    ThirdParty,
    #[serde(rename = "otp-email")]
    OtpEmail,
    #[serde(rename = "otp-phone")]
    OtpPhone,
    #[serde(rename = "totp")]
    Totp,
    #[serde(rename = "webauthn")]
    WebAuthn,
}

/// MFA requirements for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaRequirements {
    /// Required secondary factors
    #[serde(rename = "requiredSecondaryFactors")]
    pub required_secondary_factors: Vec<FactorId>,
    /// Allowed first factors
    #[serde(rename = "allowedFirstFactors")]
    pub allowed_first_factors: Vec<FactorId>,
}

/// MFA claim information in session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaClaim {
    /// Completed factors with timestamps
    #[serde(rename = "c")]
    pub completed_factors: HashMap<String, i64>,
    /// Is MFA complete
    #[serde(rename = "v")]
    pub is_complete: bool,
}

/// Request to get MFA requirements
#[derive(Serialize)]
struct GetMfaRequirementsRequest {
    #[serde(rename = "accessTokenPayload")]
    access_token_payload: serde_json::Value,
    #[serde(rename = "completedFactors")]
    completed_factors: HashMap<String, i64>,
    user: User,
    #[serde(rename = "requiredSecondaryFactorsForUser")]
    required_secondary_factors_for_user: Vec<String>,
    #[serde(rename = "requiredSecondaryFactorsForTenant")]
    required_secondary_factors_for_tenant: Vec<String>,
}

/// User information for MFA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub emails: Vec<String>,
    #[serde(rename = "phoneNumbers")]
    pub phone_numbers: Vec<String>,
    #[serde(rename = "thirdParty")]
    pub third_party: Vec<ThirdPartyInfo>,
    #[serde(rename = "loginMethods")]
    pub login_methods: Vec<LoginMethod>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeJoined")]
    pub time_joined: DateTime<Utc>,
    #[serde(rename = "tenantIds")]
    pub tenant_ids: Vec<String>,
}

/// Third party information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyInfo {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
}

/// Login method information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginMethod {
    #[serde(rename = "recipeId")]
    pub recipe_id: String,
    #[serde(rename = "recipeUserId")]
    pub recipe_user_id: String,
    #[serde(rename = "tenantIds")]
    pub tenant_ids: Vec<String>,
    pub email: Option<String>,
    #[serde(rename = "phoneNumber")]
    pub phone_number: Option<String>,
    #[serde(rename = "thirdParty")]
    pub third_party: Option<ThirdPartyInfo>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeJoined")]
    pub time_joined: DateTime<Utc>,
    pub verified: bool,
}

/// Response from getting MFA requirements
#[derive(Deserialize)]
struct GetMfaRequirementsResponse {
    status: String,
    requirements: Option<MfaRequirements>,
}

/// Request to mark factor as completed
#[derive(Serialize)]
struct MarkFactorAsCompleteRequest {
    #[serde(rename = "sessionHandle")]
    session_handle: String,
    #[serde(rename = "factorId")]
    factor_id: String,
}

/// Response from marking factor as completed
#[derive(Deserialize)]
struct MarkFactorAsCompleteResponse {
    status: String,
}

/// TOTP device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpDevice {
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "secretKey")]
    pub secret_key: String,
    pub period: Option<u32>,
    pub skew: Option<u32>,
    pub digits: Option<u32>,
}

/// Request to create TOTP device
#[derive(Serialize)]
struct CreateTotpDeviceRequest {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
}

/// Response from creating TOTP device
#[derive(Deserialize)]
struct CreateTotpDeviceResponse {
    status: String,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
    #[serde(rename = "secret")]
    secret: Option<String>,
    #[serde(rename = "qrCodeString")]
    qr_code_string: Option<String>,
}

/// Request to verify TOTP
#[derive(Serialize)]
struct VerifyTotpRequest {
    #[serde(rename = "userId")]
    user_id: String,
    token: String,
    #[serde(rename = "allowUnverifiedDevices")]
    allow_unverified_devices: bool,
}

/// Response from verifying TOTP
#[derive(Deserialize)]
struct VerifyTotpResponse {
    status: String,
    #[serde(rename = "wasAlreadyVerified")]
    was_already_verified: Option<bool>,
}

/// Get MFA requirements for a user
pub async fn get_mfa_requirements_for_auth(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    access_token_payload: serde_json::Value,
    completed_factors: HashMap<String, i64>,
    user: User,
) -> Result<MfaRequirements> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/mfa/requirements", config.api_domain);

    let request_body = GetMfaRequirementsRequest {
        access_token_payload,
        completed_factors,
        user: user.clone(),
        required_secondary_factors_for_user: Vec::new(),
        required_secondary_factors_for_tenant: Vec::new(),
    };

    let mut request = client
        .post(&url)
        .json(&request_body)
        .query(&[("tenantId", tenant_id.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let requirements_response: GetMfaRequirementsResponse = response.json().await?;

    match requirements_response.status.as_str() {
        "OK" => requirements_response.requirements.ok_or_else(|| {
            SuperTokensError::Generic(
                "MFA requirements request succeeded but no requirements returned".to_string(),
            )
        }),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown MFA requirements status: {}",
            requirements_response.status
        ))),
    }
}

/// Mark a factor as completed in the session
pub async fn mark_factor_as_complete_in_session(
    config: &SuperTokensConfig,
    session_handle: impl Into<String>,
    factor_id: FactorId,
) -> Result<()> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/mfa/complete", config.api_domain);

    let factor_id_str = match factor_id {
        FactorId::EmailPassword => "emailpassword",
        FactorId::ThirdParty => "thirdparty",
        FactorId::OtpEmail => "otp-email",
        FactorId::OtpPhone => "otp-phone",
        FactorId::Totp => "totp",
        FactorId::WebAuthn => "webauthn",
    };

    let request_body = MarkFactorAsCompleteRequest {
        session_handle: session_handle.into(),
        factor_id: factor_id_str.to_string(),
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

    let complete_response: MarkFactorAsCompleteResponse = response.json().await?;

    match complete_response.status.as_str() {
        "OK" => Ok(()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown mark factor complete status: {}",
            complete_response.status
        ))),
    }
}

/// Create a TOTP device for a user
pub async fn create_totp_device(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    device_name: Option<String>,
) -> Result<(String, String, String)> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/totp/device", config.api_domain);

    let request_body = CreateTotpDeviceRequest {
        user_id: user_id.into(),
        device_name,
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

    let device_response: CreateTotpDeviceResponse = response.json().await?;

    match device_response.status.as_str() {
        "OK" => {
            let device_name = device_response.device_name.ok_or_else(|| {
                SuperTokensError::Generic(
                    "TOTP device creation succeeded but no device name returned".to_string(),
                )
            })?;
            let secret = device_response.secret.ok_or_else(|| {
                SuperTokensError::Generic(
                    "TOTP device creation succeeded but no secret returned".to_string(),
                )
            })?;
            let qr_code_string = device_response.qr_code_string.ok_or_else(|| {
                SuperTokensError::Generic(
                    "TOTP device creation succeeded but no QR code returned".to_string(),
                )
            })?;
            Ok((device_name, secret, qr_code_string))
        }
        "DEVICE_ALREADY_EXISTS_ERROR" => Err(SuperTokensError::Generic(
            "TOTP device already exists".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown create TOTP device status: {}",
            device_response.status
        ))),
    }
}

/// Verify a TOTP token
pub async fn verify_totp_token(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    token: impl Into<String>,
    allow_unverified_devices: bool,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/totp/verify", config.api_domain);

    let request_body = VerifyTotpRequest {
        user_id: user_id.into(),
        token: token.into(),
        allow_unverified_devices,
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

    let verify_response: VerifyTotpResponse = response.json().await?;

    match verify_response.status.as_str() {
        "OK" => Ok(!verify_response.was_already_verified.unwrap_or(false)),
        "INVALID_TOTP_ERROR" => Err(SuperTokensError::InvalidCredentials),
        "LIMIT_REACHED_ERROR" => Err(SuperTokensError::Generic(
            "TOTP verification limit reached".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown verify TOTP status: {}",
            verify_response.status
        ))),
    }
}

/// Get all TOTP devices for a user
pub async fn list_totp_devices(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Vec<TotpDevice>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/totp/device/list", config.api_domain);

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

    let response_json: serde_json::Value = response.json().await?;

    if let Some(devices) = response_json.get("devices").and_then(|d| d.as_array()) {
        let totp_devices: Result<Vec<TotpDevice>> = devices
            .iter()
            .map(|d| serde_json::from_value(d.clone()).map_err(SuperTokensError::from))
            .collect();
        totp_devices
    } else {
        Ok(vec![])
    }
}

/// Remove a TOTP device
pub async fn remove_totp_device(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    device_name: impl Into<String>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/totp/device/remove", config.api_domain);

    let request_body = serde_json::json!({
        "userId": user_id.into(),
        "deviceName": device_name.into()
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

    let response_json: serde_json::Value = response.json().await?;

    match response_json.get("status").and_then(|s| s.as_str()) {
        Some("OK") => {
            let did_device_exist = response_json
                .get("didDeviceExist")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            Ok(did_device_exist)
        }
        _ => Err(SuperTokensError::Generic(
            "Unknown remove TOTP device response".to_string(),
        )),
    }
}

/// Helper function to check if MFA is complete for a session
pub fn is_mfa_complete_for_session(mfa_claim: &MfaClaim, required_factors: &[FactorId]) -> bool {
    if required_factors.is_empty() {
        return true;
    }

    mfa_claim.is_complete
        || required_factors.iter().all(|factor| {
            let factor_str = match factor {
                FactorId::EmailPassword => "emailpassword",
                FactorId::ThirdParty => "thirdparty",
                FactorId::OtpEmail => "otp-email",
                FactorId::OtpPhone => "otp-phone",
                FactorId::Totp => "totp",
                FactorId::WebAuthn => "webauthn",
            };
            mfa_claim.completed_factors.contains_key(factor_str)
        })
}


