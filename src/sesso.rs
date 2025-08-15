//! Session management module

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session information returned from SuperTokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique session handle
    pub session_handle: String,
    /// User ID associated with this session
    pub user_id: String,
    /// User data payload stored in the access token
    pub access_token_payload: serde_json::Value,
    /// Session data stored on the server
    pub user_data_in_database: serde_json::Value,
    /// Session creation time
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub time_created: DateTime<Utc>,
    /// Session expiry time
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub expiry: DateTime<Utc>,
}

/// Request payload for session verification
#[derive(Serialize)]
struct VerifySessionRequest {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "doAntiCsrfCheck")]
    do_anti_csrf_check: bool,
    #[serde(rename = "enableAntiCsrf")]
    enable_anti_csrf: bool,
}

/// Response from session verification
#[derive(Deserialize)]
struct VerifySessionResponse {
    status: String,
    session: Option<SessionInfo>,
    #[serde(rename = "accessToken")]
    #[allow(dead_code)] // May be used in future for token refresh scenarios
    access_token: Option<AccessTokenInfo>,
}

/// Access token information
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Complete API response structure for future use
struct AccessTokenInfo {
    token: String,
    expiry: i64,
    #[serde(rename = "createdTime")]
    created_time: i64,
}

/// Request for refreshing a session
#[derive(Serialize)]
struct RefreshSessionRequest {
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "enableAntiCsrf")]
    enable_anti_csrf: bool,
}

/// Response from session refresh
#[derive(Deserialize)]
struct RefreshSessionResponse {
    status: String,
    session: Option<SessionInfo>,
    #[serde(rename = "accessToken")]
    access_token: Option<AccessTokenInfo>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<RefreshTokenInfo>,
}

/// Refresh token information
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Complete API response structure for future use
struct RefreshTokenInfo {
    token: String,
    expiry: i64,
    #[serde(rename = "createdTime")]
    created_time: i64,
}

/// Request for revoking a session
#[derive(Serialize)]
struct RevokeSessionRequest {
    #[serde(rename = "sessionHandles")]
    session_handles: Vec<String>,
}

/// Verify a session using an access token
pub async fn verify_session(config: &SuperTokensConfig, access_token: &str) -> Result<SessionInfo> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/verify", config.api_domain);

    let request_body = VerifySessionRequest {
        access_token: access_token.to_string(),
        do_anti_csrf_check: false,
        enable_anti_csrf: false,
    };

    let mut request = client.post(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();

        return Err(match status {
            401 => SuperTokensError::SessionExpired,
            403 => SuperTokensError::InvalidToken("Access token is invalid".to_string()),
            _ => SuperTokensError::from_response(status, error_text),
        });
    }

    let verify_response: VerifySessionResponse = response.json().await?;

    match verify_response.status.as_str() {
        "OK" => verify_response.session.ok_or_else(|| {
            SuperTokensError::session_error(
                "Session verification succeeded but no session returned",
            )
        }),
        "UNAUTHORISED" => Err(SuperTokensError::SessionExpired),
        "TRY_REFRESH_TOKEN" => Err(SuperTokensError::InvalidToken(
            "Access token expired, refresh required".to_string(),
        )),
        _ => Err(SuperTokensError::session_error(format!(
            "Unknown session verification status: {}",
            verify_response.status
        ))),
    }
}

/// Refresh a session using a refresh token
pub async fn refresh_session(
    config: &SuperTokensConfig,
    refresh_token: &str,
) -> Result<(SessionInfo, String, String)> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/refresh", config.api_domain);

    let request_body = RefreshSessionRequest {
        refresh_token: refresh_token.to_string(),
        enable_anti_csrf: false,
    };

    let mut request = client.post(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();

        return Err(match status {
            401 => SuperTokensError::InvalidToken("Refresh token is invalid".to_string()),
            _ => SuperTokensError::from_response(status, error_text),
        });
    }

    let refresh_response: RefreshSessionResponse = response.json().await?;

    match refresh_response.status.as_str() {
        "OK" => {
            let session = refresh_response.session.ok_or_else(|| {
                SuperTokensError::session_error("Session refresh succeeded but no session returned")
            })?;
            let access_token = refresh_response.access_token.ok_or_else(|| {
                SuperTokensError::session_error(
                    "Session refresh succeeded but no access token returned",
                )
            })?;
            let new_refresh_token = refresh_response.refresh_token.ok_or_else(|| {
                SuperTokensError::session_error(
                    "Session refresh succeeded but no refresh token returned",
                )
            })?;

            Ok((session, access_token.token, new_refresh_token.token))
        }
        "UNAUTHORISED" => Err(SuperTokensError::InvalidToken(
            "Refresh token is invalid or expired".to_string(),
        )),
        _ => Err(SuperTokensError::session_error(format!(
            "Unknown session refresh status: {}",
            refresh_response.status
        ))),
    }
}

/// Revoke one or more sessions
pub async fn revoke_session(
    config: &SuperTokensConfig,
    session_handles: Vec<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/remove", config.api_domain);

    let request_body = RevokeSessionRequest { session_handles };

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

/// Update session data stored in the database
pub async fn update_session_data(
    config: &SuperTokensConfig,
    session_handle: &str,
    data: HashMap<String, serde_json::Value>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/data", config.api_domain);

    let request_body = serde_json::json!({
        "sessionHandle": session_handle,
        "userDataInDatabase": data
    });

    let mut request = client.put(&url).json(&request_body);

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

/// Get all sessions for a user
pub async fn get_user_sessions(
    config: &SuperTokensConfig,
    user_id: &str,
) -> Result<Vec<SessionInfo>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/user", config.api_domain);

    let mut request = client.get(&url).query(&[("userId", user_id)]);

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

    if let Some(sessions) = response_json
        .get("sessionHandles")
        .and_then(|s| s.as_array())
    {
        let session_infos: Result<Vec<SessionInfo>> = sessions
            .iter()
            .map(|s| serde_json::from_value(s.clone()).map_err(SuperTokensError::from))
            .collect();
        session_infos
    } else {
        Ok(vec![])
    }
}

/// Create HTTP client with common configuration
fn create_http_client(config: &SuperTokensConfig) -> Result<Client> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.options.timeout_seconds,
        ))
        .build()?;
    Ok(client)
}
