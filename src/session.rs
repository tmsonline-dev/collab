//! Enhanced session management with user roles integration

#[cfg(feature = "user-roles")]
use crate::user_roles;
use crate::{
    Result, config::SuperTokensConfig, errors::SuperTokensError, utils::create_http_client,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Enhanced session information with optional roles and permissions
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
    /// User roles (populated when user-roles feature is enabled)
    #[cfg(feature = "user-roles")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// User permissions (populated when user-roles feature is enabled)
    #[cfg(feature = "user-roles")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

/// Enhanced session context for middleware use
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_info: SessionInfo,
}

impl SessionContext {
    /// Create a new session context
    pub fn new(session_info: SessionInfo) -> Self {
        Self { session_info }
    }

    /// Check if the session user has a specific role
    #[cfg(feature = "user-roles")]
    pub fn has_role(&self, role: &str) -> bool {
        self.session_info
            .roles
            .as_ref()
            .map(|roles| roles.contains(&role.to_string()))
            .unwrap_or(false)
    }

    /// Check if the session user has any of the specified roles
    #[cfg(feature = "user-roles")]
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        if let Some(user_roles) = &self.session_info.roles {
            return roles
                .iter()
                .any(|role| user_roles.contains(&role.to_string()));
        }
        false
    }

    /// Check if the session user has all of the specified roles
    #[cfg(feature = "user-roles")]
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        if let Some(user_roles) = &self.session_info.roles {
            return roles
                .iter()
                .all(|role| user_roles.contains(&role.to_string()));
        }
        false
    }

    /// Check if the session user has a specific permission
    #[cfg(feature = "user-roles")]
    pub fn has_permission(&self, permission: &str) -> bool {
        self.session_info
            .permissions
            .as_ref()
            .map(|perms| perms.contains(&permission.to_string()))
            .unwrap_or(false)
    }

    /// Check if the session user has any of the specified permissions
    #[cfg(feature = "user-roles")]
    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        if let Some(user_permissions) = &self.session_info.permissions {
            return permissions
                .iter()
                .any(|perm| user_permissions.contains(&perm.to_string()));
        }
        false
    }

    /// Get user roles (returns empty vec if roles feature not enabled)
    pub fn get_roles(&self) -> Vec<String> {
        #[cfg(feature = "user-roles")]
        {
            self.session_info.roles.clone().unwrap_or_default()
        }
        #[cfg(not(feature = "user-roles"))]
        {
            Vec::new()
        }
    }

    /// Get user permissions (returns empty vec if roles feature not enabled)
    pub fn get_permissions(&self) -> Vec<String> {
        #[cfg(feature = "user-roles")]
        {
            self.session_info.permissions.clone().unwrap_or_default()
        }
        #[cfg(not(feature = "user-roles"))]
        {
            Vec::new()
        }
    }
}

/// Session refresh result
#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub session: SessionInfo,
    pub access_token: String,
    pub refresh_token: String,
}

/// User sessions information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    #[serde(rename = "sessionHandle")]
    pub session_handle: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "userDataInJWT")]
    pub user_data_in_jwt: serde_json::Value,
    #[serde(rename = "userDataInDatabase")]
    pub user_data_in_database: serde_json::Value,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub expiry: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeCreated")]
    pub time_created: DateTime<Utc>,
}

// Internal request/response structures

#[derive(Serialize)]
struct VerifySessionRequest {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "doAntiCsrfCheck")]
    do_anti_csrf_check: bool,
    #[serde(rename = "enableAntiCsrf")]
    enable_anti_csrf: bool,
}

#[derive(Deserialize)]
struct VerifySessionResponse {
    status: String,
    session: Option<SessionInfo>,
    #[serde(rename = "accessToken")]
    #[allow(dead_code)]
    access_token: Option<AccessTokenInfo>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AccessTokenInfo {
    token: String,
    expiry: i64,
    #[serde(rename = "createdTime")]
    created_time: i64,
}

#[derive(Serialize)]
struct RefreshSessionRequest {
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "enableAntiCsrf")]
    enable_anti_csrf: bool,
}

#[derive(Deserialize)]
struct RefreshSessionResponse {
    status: String,
    session: Option<SessionInfo>,
    #[serde(rename = "accessToken")]
    access_token: Option<AccessTokenInfo>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<RefreshTokenInfo>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RefreshTokenInfo {
    token: String,
    expiry: i64,
    #[serde(rename = "createdTime")]
    created_time: i64,
}

#[derive(Serialize)]
struct RevokeSessionRequest {
    #[serde(rename = "sessionHandles")]
    session_handles: Vec<String>,
}

#[derive(Deserialize)]
struct RevokeSessionResponse {
    status: String,
    #[serde(rename = "sessionHandlesRevoked")]
    session_handles_revoked: Option<Vec<String>>,
}

#[derive(Serialize)]
struct UpdateSessionDataRequest {
    #[serde(rename = "sessionHandle")]
    session_handle: String,
    #[serde(rename = "userDataInDatabase")]
    user_data_in_database: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct UpdateSessionDataResponse {
    status: String,
}

#[derive(Deserialize)]
struct GetUserSessionsResponse {
    status: String,
    #[serde(rename = "sessionHandles")]
    session_handles: Option<Vec<String>>,
}

/// Verify a session using an access token with optional roles/permissions loading
pub async fn verify_session(config: &SuperTokensConfig, access_token: &str) -> Result<SessionInfo> {
    // First do the standard session verification
    let mut session_info = verify_session_basic(config, access_token).await?;

    // If user-roles feature is enabled, load roles and permissions
    #[cfg(feature = "user-roles")]
    {
        if let Ok(roles) =
            user_roles::get_roles_for_user(config, "public", &session_info.user_id).await
        {
            // Get all permissions from all roles
            let mut all_permissions = Vec::new();
            for role in &roles {
                if let Ok(permissions) = user_roles::get_permissions_for_role(config, role).await {
                    all_permissions.extend(permissions);
                }
            }
            // Remove duplicates
            all_permissions.sort();
            all_permissions.dedup();

            session_info.roles = Some(roles);
            session_info.permissions = Some(all_permissions);
        }
    }

    Ok(session_info)
}

/// Basic session verification without roles/permissions
async fn verify_session_basic(
    config: &SuperTokensConfig,
    access_token: &str,
) -> Result<SessionInfo> {
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
) -> Result<RefreshResult> {
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

            let access_token = refresh_response
                .access_token
                .ok_or_else(|| {
                    SuperTokensError::session_error(
                        "Session refresh succeeded but no access token returned",
                    )
                })?
                .token;

            let refresh_token = refresh_response
                .refresh_token
                .ok_or_else(|| {
                    SuperTokensError::session_error(
                        "Session refresh succeeded but no refresh token returned",
                    )
                })?
                .token;

            Ok(RefreshResult {
                session,
                access_token,
                refresh_token,
            })
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
) -> Result<Vec<String>> {
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

    let revoke_response: RevokeSessionResponse = response.json().await?;

    match revoke_response.status.as_str() {
        "OK" => Ok(revoke_response.session_handles_revoked.unwrap_or_default()),
        _ => Err(SuperTokensError::session_error(format!(
            "Unknown session revocation status: {}",
            revoke_response.status
        ))),
    }
}

/// Update session data in the database
pub async fn update_session_data(
    config: &SuperTokensConfig,
    session_handle: &str,
    user_data: HashMap<String, serde_json::Value>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/data", config.api_domain);

    let request_body = UpdateSessionDataRequest {
        session_handle: session_handle.to_string(),
        user_data_in_database: user_data,
    };

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

    let update_response: UpdateSessionDataResponse = response.json().await?;

    match update_response.status.as_str() {
        "OK" => Ok(()),
        "UNAUTHORISED" => Err(SuperTokensError::InvalidToken(
            "Session handle is invalid".to_string(),
        )),
        _ => Err(SuperTokensError::session_error(format!(
            "Unknown session data update status: {}",
            update_response.status
        ))),
    }
}

/// Get all session handles for a user
pub async fn get_user_sessions(config: &SuperTokensConfig, user_id: &str) -> Result<Vec<String>> {
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

    let sessions_response: GetUserSessionsResponse = response.json().await?;

    match sessions_response.status.as_str() {
        "OK" => Ok(sessions_response.session_handles.unwrap_or_default()),
        _ => Err(SuperTokensError::session_error(format!(
            "Unknown get user sessions status: {}",
            sessions_response.status
        ))),
    }
}

/// Revoke all sessions for a user
pub async fn revoke_all_user_sessions(
    config: &SuperTokensConfig,
    user_id: &str,
) -> Result<Vec<String>> {
    let session_handles = get_user_sessions(config, user_id).await?;
    if session_handles.is_empty() {
        return Ok(vec![]);
    }
    revoke_session(config, session_handles).await
}

/// Get detailed session information by session handle
pub async fn get_session_information(
    config: &SuperTokensConfig,
    session_handle: &str,
) -> Result<Option<SessionInfo>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session", config.api_domain);

    let mut request = client.get(&url).query(&[("sessionHandle", session_handle)]);

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

    let session_info: SessionInfo = response.json().await?;
    Ok(Some(session_info))
}

/// Update access token payload
pub async fn update_access_token_payload(
    config: &SuperTokensConfig,
    session_handle: &str,
    new_access_token_payload: HashMap<String, serde_json::Value>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/jwt/data", config.api_domain);

    let request_body = serde_json::json!({
        "sessionHandle": session_handle,
        "userDataInJWT": new_access_token_payload
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

    let response_json: serde_json::Value = response.json().await?;

    match response_json.get("status").and_then(|s| s.as_str()) {
        Some("OK") => Ok(()),
        Some("UNAUTHORISED") => Err(SuperTokensError::InvalidToken(
            "Session handle is invalid".to_string(),
        )),
        _ => Err(SuperTokensError::session_error(
            "Unknown access token payload update response".to_string(),
        )),
    }
}

/// Check if a session exists and is valid
pub async fn does_session_exist(config: &SuperTokensConfig, session_handle: &str) -> Result<bool> {
    match get_session_information(config, session_handle).await? {
        Some(session_info) => {
            // Check if session is expired
            let now = chrono::Utc::now();
            Ok(session_info.expiry > now)
        }
        None => Ok(false),
    }
}

// Re-export the basic functions for backward compatibility
pub use verify_session as verify_session_with_roles;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::create_test_config;

    #[test]
    fn test_session_context_creation() {
        let session_info = SessionInfo {
            session_handle: "test_handle".to_string(),
            user_id: "test_user".to_string(),
            access_token_payload: serde_json::json!({}),
            user_data_in_database: serde_json::json!({}),
            time_created: chrono::Utc::now(),
            expiry: chrono::Utc::now() + chrono::Duration::hours(1),
            #[cfg(feature = "user-roles")]
            roles: Some(vec!["admin".to_string()]),
            #[cfg(feature = "user-roles")]
            permissions: Some(vec!["read:all".to_string()]),
        };

        let context = SessionContext::new(session_info);
        assert_eq!(context.session_info.user_id, "test_user");

        #[cfg(feature = "user-roles")]
        {
            assert!(context.has_role("admin"));
            assert!(context.has_permission("read:all"));
            assert!(!context.has_role("user"));
        }
    }

    #[tokio::test]
    #[ignore] // Requires SuperTokens Core running with valid tokens
    async fn test_session_operations() {
        use crate::session::{refresh_session, revoke_session, verify_session};
        let config = create_test_config();

        // NOTE: Replace these placeholders with real tokens generated via SuperTokens Core.
        let test_access_token = "eyJhbGciOiJSUzI1NiIsInR...";
        let test_refresh_token = "def50200b0c...";
        let test_session_handle = "test_session_handle";

        // 1. Test session verification
        let session_res = verify_session(&config, test_access_token).await;
        assert!(
            session_res.is_ok(),
            "Session verification failed: {:?}",
            session_res.err()
        );
        let session_info = session_res.unwrap();
        assert_eq!(
            session_info.user_id, "test_user_id",
            "Unexpected user_id in session"
        );

        // 2. Test session refresh
        let refresh_res = refresh_session(&config, test_refresh_token).await;
        assert!(
            refresh_res.is_ok(),
            "Session refresh failed: {:?}",
            refresh_res.err()
        );
        let refresh_result = refresh_res.unwrap();
        assert!(
            refresh_result.access_token.len() > 0,
            "New access token should not be empty"
        );
        assert!(
            refresh_result.refresh_token.len() > 0,
            "New refresh token should not be empty"
        );

        // 3. Test session revocation
        let revoke_res = revoke_session(&config, vec![test_session_handle.to_string()]).await;
        assert!(
            revoke_res.is_ok(),
            "Session revocation failed: {:?}",
            revoke_res.err()
        );
        let revoked_handles = revoke_res.unwrap();
        assert!(
            revoked_handles.contains(&test_session_handle.to_string()),
            "Revoked handles should include the test session handle"
        );
    }
}
