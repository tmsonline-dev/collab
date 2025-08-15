//! Dashboard management APIs for user administration

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Dashboard user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardUser {
    pub email: String,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeJoined")]
    pub time_joined: DateTime<Utc>,
}

/// User search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSearchResult {
    pub users: Vec<DashboardUserInfo>,
    #[serde(rename = "nextPaginationToken")]
    pub next_pagination_token: Option<String>,
}

/// Dashboard user information with additional details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardUserInfo {
    pub id: String,
    #[serde(rename = "isPrimaryUser")]
    pub is_primary_user: bool,
    pub emails: Vec<String>,
    #[serde(rename = "phoneNumbers")]
    pub phone_numbers: Vec<String>,
    #[serde(rename = "thirdParty")]
    pub third_party: Vec<ThirdPartyUserInfo>,
    #[serde(rename = "loginMethods")]
    pub login_methods: Vec<LoginMethodInfo>,
    #[serde(rename = "tenantIds")]
    pub tenant_ids: Vec<String>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeJoined")]
    pub time_joined: DateTime<Utc>,
}

/// Third party user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyUserInfo {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
}

/// Login method information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginMethodInfo {
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
    pub third_party: Option<ThirdPartyUserInfo>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeJoined")]
    pub time_joined: DateTime<Utc>,
    pub verified: bool,
}

/// Session information for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSessionInfo {
    #[serde(rename = "sessionDataInDatabase")]
    pub session_data: serde_json::Value,
    #[serde(rename = "accessTokenPayload")]
    pub access_token_payload: serde_json::Value,
    #[serde(rename = "sessionHandle")]
    pub session_handle: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub expiry: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeCreated")]
    pub time_created: DateTime<Utc>,
}

/// User metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMetadata {
    pub data: HashMap<String, serde_json::Value>,
}

/// Request for creating dashboard user
#[derive(Serialize)]
struct CreateDashboardUserRequest {
    email: String,
    password: String,
}

/// Response from creating dashboard user
#[derive(Deserialize)]
struct CreateDashboardUserResponse {
    status: String,
}

/// Request for updating dashboard user
#[derive(Serialize)]
struct UpdateDashboardUserRequest {
    email: String,
    #[serde(rename = "newEmail")]
    new_email: Option<String>,
    #[serde(rename = "newPassword")]
    new_password: Option<String>,
}

/// Response from updating dashboard user
#[derive(Deserialize)]
struct UpdateDashboardUserResponse {
    status: String,
}

/// Request for deleting dashboard user
#[derive(Serialize)]
struct DeleteDashboardUserRequest {
    email: String,
}

/// Response from deleting dashboard user
#[derive(Deserialize)]
struct DeleteDashboardUserResponse {
    status: String,
    #[serde(rename = "didUserExist")]
    did_user_exist: Option<bool>,
}

/// Response for getting users
#[derive(Deserialize)]
struct GetUsersResponse {
    status: String,
    users: Option<Vec<DashboardUserInfo>>,
    #[serde(rename = "nextPaginationToken")]
    next_pagination_token: Option<String>,
}

/// Response for getting user sessions
#[derive(Deserialize)]
struct GetUserSessionsResponse {
    status: String,
    sessions: Option<Vec<DashboardSessionInfo>>,
}

/// Response for getting user metadata
#[derive(Deserialize)]
struct GetUserMetadataResponse {
    status: String,
    metadata: Option<serde_json::Value>,
}

/// Request for updating user metadata
#[derive(Serialize)]
struct UpdateUserMetadataRequest {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "metadataUpdate")]
    metadata_update: serde_json::Value,
}

/// Response from updating user metadata
#[derive(Deserialize)]
struct UpdateUserMetadataResponse {
    status: String,
}

/// Create a new dashboard user with email and password
pub async fn create_dashboard_user(
    config: &SuperTokensConfig,
    email: impl Into<String>,
    password: impl Into<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/dashboard/user", config.api_domain);

    let request_body = CreateDashboardUserRequest {
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

    let create_response: CreateDashboardUserResponse = response.json().await?;

    match create_response.status.as_str() {
        "OK" => Ok(()),
        "EMAIL_ALREADY_EXISTS_ERROR" => Err(SuperTokensError::EmailAlreadyExists),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown create dashboard user status: {}",
            create_response.status
        ))),
    }
}

/// Update dashboard user email or password
pub async fn update_dashboard_user(
    config: &SuperTokensConfig,
    email: impl Into<String>,
    new_email: Option<String>,
    new_password: Option<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/dashboard/user", config.api_domain);

    let request_body = UpdateDashboardUserRequest {
        email: email.into(),
        new_email,
        new_password,
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

    let update_response: UpdateDashboardUserResponse = response.json().await?;

    match update_response.status.as_str() {
        "OK" => Ok(()),
        "EMAIL_ALREADY_EXISTS_ERROR" => Err(SuperTokensError::EmailAlreadyExists),
        "UNKNOWN_USER_ID_ERROR" => Err(SuperTokensError::UserNotFound),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown update dashboard user status: {}",
            update_response.status
        ))),
    }
}

/// Delete a dashboard user
pub async fn delete_dashboard_user(
    config: &SuperTokensConfig,
    email: impl Into<String>,
) -> Result<bool> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/dashboard/user", config.api_domain);

    let request_body = DeleteDashboardUserRequest {
        email: email.into(),
    };

    let mut request = client.delete(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let delete_response: DeleteDashboardUserResponse = response.json().await?;

    match delete_response.status.as_str() {
        "OK" => Ok(delete_response.did_user_exist.unwrap_or(false)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown delete dashboard user status: {}",
            delete_response.status
        ))),
    }
}

/// Get paginated list of users
pub async fn get_users(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    limit: Option<u32>,
    pagination_token: Option<String>,
    include_recipe_ids: Option<Vec<String>>,
) -> Result<UserSearchResult> {
    let client = create_http_client(config)?;
    let url = format!("{}/users", config.api_domain);

    let mut query_params = Vec::new();

    if let Some(tenant) = tenant_id {
        query_params.push(("tenantId", tenant));
    }
    if let Some(limit_val) = limit {
        query_params.push(("limit", limit_val.to_string()));
    }
    if let Some(token) = pagination_token {
        query_params.push(("paginationToken", token));
    }
    if let Some(recipe_ids) = include_recipe_ids {
        query_params.push(("includeRecipeIds", recipe_ids.join(",")));
    }

    let mut request = client.get(&url).query(&query_params);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let users_response: GetUsersResponse = response.json().await?;

    match users_response.status.as_str() {
        "OK" => Ok(UserSearchResult {
            users: users_response.users.unwrap_or_default(),
            next_pagination_token: users_response.next_pagination_token,
        }),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get users status: {}",
            users_response.status
        ))),
    }
}

/// Get user by ID
pub async fn get_user_by_id(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Option<DashboardUserInfo>> {
    let client = create_http_client(config)?;
    let url = format!("{}/user/id", config.api_domain);

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

    let user: DashboardUserInfo = response.json().await?;
    Ok(Some(user))
}

/// Get all sessions for a user
pub async fn get_user_sessions(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Vec<DashboardSessionInfo>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/user", config.api_domain);

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

    let sessions_response: GetUserSessionsResponse = response.json().await?;

    match sessions_response.status.as_str() {
        "OK" => Ok(sessions_response.sessions.unwrap_or_default()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get user sessions status: {}",
            sessions_response.status
        ))),
    }
}

/// Revoke all sessions for a user
pub async fn revoke_all_sessions_for_user(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Vec<String>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/session/remove", config.api_domain);

    let request_body = serde_json::json!({
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

    let response_json: serde_json::Value = response.json().await?;

    if let Some(session_handles) = response_json
        .get("sessionHandlesRevoked")
        .and_then(|s| s.as_array())
    {
        let handles: Vec<String> = session_handles
            .iter()
            .filter_map(|h| h.as_str().map(|s| s.to_string()))
            .collect();
        Ok(handles)
    } else {
        Ok(vec![])
    }
}

/// Get user metadata
pub async fn get_user_metadata(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<UserMetadata> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/usermetadata", config.api_domain);

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

    let metadata_response: GetUserMetadataResponse = response.json().await?;

    match metadata_response.status.as_str() {
        "OK" => {
            let metadata_value = metadata_response.metadata.unwrap_or(serde_json::json!({}));
            let data: HashMap<String, serde_json::Value> =
                if let Some(obj) = metadata_value.as_object() {
                    obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                } else {
                    HashMap::new()
                };

            Ok(UserMetadata { data })
        }
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get user metadata status: {}",
            metadata_response.status
        ))),
    }
}

/// Update user metadata
pub async fn update_user_metadata(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    metadata_update: serde_json::Value,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/usermetadata", config.api_domain);

    let request_body = UpdateUserMetadataRequest {
        user_id: user_id.into(),
        metadata_update,
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

    let update_response: UpdateUserMetadataResponse = response.json().await?;

    match update_response.status.as_str() {
        "OK" => Ok(()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown update user metadata status: {}",
            update_response.status
        ))),
    }
}

/// Delete user metadata
pub async fn clear_user_metadata(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/usermetadata/remove", config.api_domain);

    let request_body = serde_json::json!({
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

    Ok(())
}

/// Update user email (for email/password users)
pub async fn update_user_email(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
    new_email: impl Into<String>,
    apply_email_verification_required_flag: Option<bool>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user", config.api_domain);

    let request_body = serde_json::json!({
        "recipeUserId": recipe_user_id.into(),
        "email": new_email.into(),
        "applyPasswordPolicy": apply_email_verification_required_flag.unwrap_or(true)
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

/// Update user password (for email/password users)
pub async fn update_user_password(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
    new_password: impl Into<String>,
    apply_password_policy: Option<bool>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/password", config.api_domain);

    let request_body = serde_json::json!({
        "recipeUserId": recipe_user_id.into(),
        "newPassword": new_password.into(),
        "applyPasswordPolicy": apply_password_policy.unwrap_or(true)
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
            400 => SuperTokensError::Generic("Password policy violation".to_string()),
            404 => SuperTokensError::UserNotFound,
            _ => SuperTokensError::from_response(status, error_text),
        });
    }

    Ok(())
}

/// Get tenant information
pub async fn get_tenant_info(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
) -> Result<serde_json::Value> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/tenant", config.api_domain);

    let mut request = client.get(&url).query(&[("tenantId", tenant_id.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let tenant_info: serde_json::Value = response.json().await?;
    Ok(tenant_info)
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
