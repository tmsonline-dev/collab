//! User roles and permissions management (RBAC)

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Role information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name/identifier
    pub role: String,
    /// Permissions associated with this role
    pub permissions: Vec<String>,
}

/// User role assignment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    /// User ID
    pub user_id: String,
    /// Role assigned to the user
    pub role: String,
    /// Tenant ID (for multi-tenancy)
    pub tenant_id: String,
}

/// Request for creating a role or adding permissions
#[derive(Serialize)]
struct CreateRoleRequest {
    role: String,
    permissions: Vec<String>,
}

/// Response from creating a role
#[derive(Deserialize)]
struct CreateRoleResponse {
    status: String,
    #[serde(rename = "createdNewRole")]
    created_new_role: Option<bool>,
}

/// Request for adding role to user
#[derive(Serialize)]
struct AddRoleToUserRequest {
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

/// Response from adding role to user
#[derive(Deserialize)]
struct AddRoleToUserResponse {
    status: String,
    #[serde(rename = "didUserAlreadyHaveRole")]
    did_user_already_have_role: Option<bool>,
}

/// Request for removing role from user
#[derive(Serialize)]
struct RemoveUserRoleRequest {
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

/// Response from removing role from user
#[derive(Deserialize)]
struct RemoveUserRoleResponse {
    status: String,
    #[serde(rename = "didUserHaveRole")]
    did_user_have_role: Option<bool>,
}

/// Response for getting user roles
#[derive(Deserialize)]
struct GetRolesForUserResponse {
    status: String,
    roles: Option<Vec<String>>,
}

/// Response for getting users with role
#[derive(Deserialize)]
struct GetUsersWithRoleResponse {
    status: String,
    users: Option<Vec<String>>,
}

/// Response for getting permissions for role
#[derive(Deserialize)]
struct GetPermissionsForRoleResponse {
    status: String,
    permissions: Option<Vec<String>>,
}

/// Response for getting all roles
#[derive(Deserialize)]
struct GetAllRolesResponse {
    status: String,
    roles: Option<Vec<String>>,
}

/// Request for removing permissions from role
#[derive(Serialize)]
struct RemovePermissionsFromRoleRequest {
    role: String,
    permissions: Vec<String>,
}

/// Response from removing permissions from role
#[derive(Deserialize)]
struct RemovePermissionsFromRoleResponse {
    status: String,
}

/// Response for getting roles that have permission
#[derive(Deserialize)]
struct GetRolesThatHavePermissionResponse {
    status: String,
    roles: Option<Vec<String>>,
}

/// Create a new role or add permissions to an existing role
pub async fn create_new_role_or_add_permissions(
    config: &SuperTokensConfig,
    role: impl Into<String>,
    permissions: Vec<String>,
) -> Result<bool> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/role", config.api_domain);

    let request_body = CreateRoleRequest {
        role: role.into(),
        permissions,
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

    let create_response: CreateRoleResponse = response.json().await?;

    match create_response.status.as_str() {
        "OK" => Ok(create_response.created_new_role.unwrap_or(false)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown create role status: {}",
            create_response.status
        ))),
    }
}

/// Add a role to a user
pub async fn add_role_to_user(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    user_id: impl Into<String>,
    role: impl Into<String>,
) -> Result<bool> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/role", config.api_domain);

    let request_body = AddRoleToUserRequest {
        user_id: user_id.into(),
        role: role.into(),
        tenant_id: tenant_id.into(),
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

    let add_response: AddRoleToUserResponse = response.json().await?;

    match add_response.status.as_str() {
        "OK" => Ok(!add_response.did_user_already_have_role.unwrap_or(false)),
        "UNKNOWN_ROLE_ERROR" => Err(SuperTokensError::Generic("Unknown role".to_string())),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown add role to user status: {}",
            add_response.status
        ))),
    }
}

/// Remove a role from a user
pub async fn remove_user_role(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    user_id: impl Into<String>,
    role: impl Into<String>,
) -> Result<bool> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/role/remove", config.api_domain);

    let request_body = RemoveUserRoleRequest {
        user_id: user_id.into(),
        role: role.into(),
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

    let remove_response: RemoveUserRoleResponse = response.json().await?;

    match remove_response.status.as_str() {
        "OK" => Ok(remove_response.did_user_have_role.unwrap_or(false)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown remove user role status: {}",
            remove_response.status
        ))),
    }
}

/// Get all roles for a user
pub async fn get_roles_for_user(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    user_id: impl Into<String>,
) -> Result<Vec<String>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/user/roles", config.api_domain);

    let mut request = client
        .get(&url)
        .query(&[("userId", user_id.into()), ("tenantId", tenant_id.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let roles_response: GetRolesForUserResponse = response.json().await?;

    match roles_response.status.as_str() {
        "OK" => Ok(roles_response.roles.unwrap_or_default()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get roles for user status: {}",
            roles_response.status
        ))),
    }
}

/// Get all users that have a specific role
pub async fn get_users_that_have_role(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    role: impl Into<String>,
) -> Result<Vec<String>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/role/users", config.api_domain);

    let mut request = client
        .get(&url)
        .query(&[("role", role.into()), ("tenantId", tenant_id.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let users_response: GetUsersWithRoleResponse = response.json().await?;

    match users_response.status.as_str() {
        "OK" => Ok(users_response.users.unwrap_or_default()),
        "UNKNOWN_ROLE_ERROR" => Err(SuperTokensError::Generic("Unknown role".to_string())),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get users with role status: {}",
            users_response.status
        ))),
    }
}

/// Get all permissions for a role
pub async fn get_permissions_for_role(
    config: &SuperTokensConfig,
    role: impl Into<String>,
) -> Result<Vec<String>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/role/permissions", config.api_domain);

    let mut request = client.get(&url).query(&[("role", role.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let permissions_response: GetPermissionsForRoleResponse = response.json().await?;

    match permissions_response.status.as_str() {
        "OK" => Ok(permissions_response.permissions.unwrap_or_default()),
        "UNKNOWN_ROLE_ERROR" => Err(SuperTokensError::Generic("Unknown role".to_string())),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get permissions for role status: {}",
            permissions_response.status
        ))),
    }
}

/// Get all roles
pub async fn get_all_roles(config: &SuperTokensConfig) -> Result<Vec<String>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/roles", config.api_domain);

    let mut request = client.get(&url);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let roles_response: GetAllRolesResponse = response.json().await?;

    match roles_response.status.as_str() {
        "OK" => Ok(roles_response.roles.unwrap_or_default()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get all roles status: {}",
            roles_response.status
        ))),
    }
}

/// Remove permissions from a role
pub async fn remove_permissions_from_role(
    config: &SuperTokensConfig,
    role: impl Into<String>,
    permissions: Vec<String>,
) -> Result<()> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/role/permissions/remove", config.api_domain);

    let request_body = RemovePermissionsFromRoleRequest {
        role: role.into(),
        permissions,
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

    let remove_response: RemovePermissionsFromRoleResponse = response.json().await?;

    match remove_response.status.as_str() {
        "OK" => Ok(()),
        "UNKNOWN_ROLE_ERROR" => Err(SuperTokensError::Generic("Unknown role".to_string())),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown remove permissions from role status: {}",
            remove_response.status
        ))),
    }
}

/// Get all roles that have a specific permission
pub async fn get_roles_that_have_permission(
    config: &SuperTokensConfig,
    permission: impl Into<String>,
) -> Result<Vec<String>> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/permission/roles", config.api_domain);

    let mut request = client.get(&url).query(&[("permission", permission.into())]);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let roles_response: GetRolesThatHavePermissionResponse = response.json().await?;

    match roles_response.status.as_str() {
        "OK" => Ok(roles_response.roles.unwrap_or_default()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get roles that have permission status: {}",
            roles_response.status
        ))),
    }
}

/// Delete a role
pub async fn delete_role(config: &SuperTokensConfig, role: impl Into<String>) -> Result<bool> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/role/remove", config.api_domain);

    let request_body = serde_json::json!({
        "role": role.into()
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
            let did_role_exist = response_json
                .get("didRoleExist")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            Ok(did_role_exist)
        }
        _ => Err(SuperTokensError::Generic(
            "Unknown delete role response".to_string(),
        )),
    }
}

/// Helper function to check if user has specific role
pub async fn user_has_role(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    user_id: impl Into<String>,
    role: impl Into<String>,
) -> Result<bool> {
    let user_id = user_id.into();
    let role = role.into();
    let roles = get_roles_for_user(config, tenant_id, &user_id).await?;
    Ok(roles.contains(&role))
}

/// Helper function to check if user has specific permission
pub async fn user_has_permission(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    user_id: impl Into<String>,
    permission: impl Into<String>,
) -> Result<bool> {
    let permission = permission.into();
    let roles = get_roles_for_user(config, tenant_id, user_id).await?;

    for role in roles {
        let permissions = get_permissions_for_role(config, &role).await?;
        if permissions.contains(&permission) {
            return Ok(true);
        }
    }

    Ok(false)
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
