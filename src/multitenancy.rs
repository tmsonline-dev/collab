//! Multi-tenancy management recipe

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tenant configuration for creating or updating tenants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    /// First factor authentication methods enabled for this tenant
    #[serde(rename = "firstFactors")]
    pub first_factors: Option<Vec<String>>,
    /// Required secondary factor authentication methods
    #[serde(rename = "requiredSecondaryFactors")]
    pub required_secondary_factors: Option<Vec<String>>,
    /// Core configuration overrides for this tenant
    #[serde(rename = "coreConfig")]
    pub core_config: Option<HashMap<String, serde_json::Value>>,
}

/// Tenant information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "firstFactors")]
    pub first_factors: Vec<String>,
    #[serde(rename = "requiredSecondaryFactors")]
    pub required_secondary_factors: Vec<String>,
    #[serde(rename = "coreConfig")]
    pub core_config: HashMap<String, serde_json::Value>,
}

/// Third party provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(rename = "thirdPartyId")]
    pub third_party_id: String,
    pub name: Option<String>,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    #[serde(rename = "clientType")]
    pub client_type: Option<String>,
    pub scope: Option<Vec<String>>,
    #[serde(rename = "authorizationEndpoint")]
    pub authorization_endpoint: Option<String>,
    #[serde(rename = "authorizationEndpointQueryParams")]
    pub authorization_endpoint_query_params: Option<HashMap<String, String>>,
    #[serde(rename = "tokenEndpoint")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "tokenEndpointBodyParams")]
    pub token_endpoint_body_params: Option<HashMap<String, String>>,
    #[serde(rename = "userInfoEndpoint")]
    pub user_info_endpoint: Option<String>,
    #[serde(rename = "userInfoEndpointQueryParams")]
    pub user_info_endpoint_query_params: Option<HashMap<String, String>>,
    #[serde(rename = "userInfoEndpointHeaders")]
    pub user_info_endpoint_headers: Option<HashMap<String, String>>,
    #[serde(rename = "jwksURI")]
    pub jwks_uri: Option<String>,
    #[serde(rename = "oidcDiscoveryEndpoint")]
    pub oidc_discovery_endpoint: Option<String>,
    #[serde(rename = "userInfoMap")]
    pub user_info_map: Option<UserInfoMap>,
}

/// User info mapping from third party provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoMap {
    #[serde(rename = "fromIdTokenPayload")]
    pub from_id_token_payload: Option<UserInfoMapFields>,
    #[serde(rename = "fromUserInfoAPI")]
    pub from_user_info_api: Option<UserInfoMapFields>,
}

/// User info field mappings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoMapFields {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: Option<String>,
}

/// Request for creating or updating tenant
#[derive(Serialize)]
struct CreateOrUpdateTenantRequest {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(flatten)]
    config: TenantConfig,
}

/// Response from creating or updating tenant
#[derive(Deserialize)]
struct CreateOrUpdateTenantResponse {
    status: String,
    #[serde(rename = "createdNew")]
    created_new: Option<bool>,
}

/// Response from getting tenant
#[derive(Deserialize)]
struct GetTenantResponse {
    status: String,
    #[serde(flatten)]
    tenant: Option<Tenant>,
}

/// Response from listing all tenants
#[derive(Deserialize)]
struct ListAllTenantsResponse {
    status: String,
    tenants: Option<Vec<Tenant>>,
}

/// Response from deleting tenant
#[derive(Deserialize)]
struct DeleteTenantResponse {
    status: String,
    #[serde(rename = "didExist")]
    did_exist: Option<bool>,
}

/// Request for associating user to tenant
#[derive(Serialize)]
struct AssociateUserToTenantRequest {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "recipeUserId")]
    recipe_user_id: String,
}

/// Response from associating user to tenant
#[derive(Deserialize)]
struct AssociateUserToTenantResponse {
    status: String,
    #[serde(rename = "wasAlreadyAssociated")]
    was_already_associated: Option<bool>,
}

/// Built-in first factors
pub struct FirstFactors;

impl FirstFactors {
    pub const EMAIL_PASSWORD: &'static str = "emailpassword";
    pub const THIRD_PARTY: &'static str = "thirdparty";
    pub const OTP_EMAIL: &'static str = "otp-email";
    pub const OTP_PHONE: &'static str = "otp-phone";
    pub const LINK_EMAIL: &'static str = "link-email";
    pub const LINK_PHONE: &'static str = "link-phone";
}

/// Built-in second factors
pub struct SecondFactors;

impl SecondFactors {
    pub const OTP_EMAIL: &'static str = "otp-email";
    pub const OTP_PHONE: &'static str = "otp-phone";
    pub const TOTP: &'static str = "totp";
    pub const WEBAUTHN: &'static str = "webauthn";
}

/// Create or update a tenant
pub async fn create_or_update_tenant(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    tenant_config: TenantConfig,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/tenant", config.api_domain);

    let request_body = CreateOrUpdateTenantRequest {
        tenant_id: tenant_id.into(),
        config: tenant_config,
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

    let tenant_response: CreateOrUpdateTenantResponse = response.json().await?;

    match tenant_response.status.as_str() {
        "OK" => Ok(tenant_response.created_new.unwrap_or(false)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown create/update tenant status: {}",
            tenant_response.status
        ))),
    }
}

/// Get tenant information
pub async fn get_tenant(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
) -> Result<Option<Tenant>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/tenant", config.api_domain);

    let mut request = client.get(&url).query(&[("tenantId", tenant_id.into())]);

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

    let tenant_response: GetTenantResponse = response.json().await?;

    match tenant_response.status.as_str() {
        "OK" => Ok(tenant_response.tenant),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown get tenant status: {}",
            tenant_response.status
        ))),
    }
}

/// List all tenants
pub async fn list_all_tenants(config: &SuperTokensConfig) -> Result<Vec<Tenant>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/tenant/list", config.api_domain);

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

    let tenants_response: ListAllTenantsResponse = response.json().await?;

    match tenants_response.status.as_str() {
        "OK" => Ok(tenants_response.tenants.unwrap_or_default()),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown list tenants status: {}",
            tenants_response.status
        ))),
    }
}

/// Delete a tenant
pub async fn delete_tenant(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/tenant/remove", config.api_domain);

    let request_body = serde_json::json!({
        "tenantId": tenant_id.into()
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

    let delete_response: DeleteTenantResponse = response.json().await?;

    match delete_response.status.as_str() {
        "OK" => Ok(delete_response.did_exist.unwrap_or(false)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown delete tenant status: {}",
            delete_response.status
        ))),
    }
}

/// Create or update third party provider configuration for a tenant
pub async fn create_or_update_third_party_config(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    provider_config: ProviderConfig,
    skip_validation: Option<bool>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!(
        "{}/recipe/multitenancy/config/thirdparty",
        config.api_domain
    );

    let mut request_body = serde_json::to_value(&provider_config)?;
    request_body["tenantId"] = serde_json::Value::String(tenant_id.into());

    if let Some(skip_val) = skip_validation {
        request_body["skipValidation"] = serde_json::Value::Bool(skip_val);
    }

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
        Some("OK") => {
            let created_new = response_json
                .get("createdNew")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            Ok(created_new)
        }
        _ => Err(SuperTokensError::Generic(
            "Unknown third party config response".to_string(),
        )),
    }
}

/// Delete third party provider configuration for a tenant
pub async fn delete_third_party_config(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    third_party_id: impl Into<String>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!(
        "{}/recipe/multitenancy/config/thirdparty/remove",
        config.api_domain
    );

    let request_body = serde_json::json!({
        "tenantId": tenant_id.into(),
        "thirdPartyId": third_party_id.into()
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
            let did_exist = response_json
                .get("didConfigExist")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            Ok(did_exist)
        }
        _ => Err(SuperTokensError::Generic(
            "Unknown delete third party config response".to_string(),
        )),
    }
}

/// Associate a user with a tenant
pub async fn associate_user_to_tenant(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    recipe_user_id: impl Into<String>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/multitenancy/tenant/user", config.api_domain);

    let request_body = AssociateUserToTenantRequest {
        tenant_id: tenant_id.into(),
        recipe_user_id: recipe_user_id.into(),
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

    let associate_response: AssociateUserToTenantResponse = response.json().await?;

    match associate_response.status.as_str() {
        "OK" => Ok(!associate_response.was_already_associated.unwrap_or(true)),
        "UNKNOWN_USER_ID_ERROR" => Err(SuperTokensError::UserNotFound),
        "EMAIL_ALREADY_EXISTS_ERROR" => Err(SuperTokensError::EmailAlreadyExists),
        "PHONE_NUMBER_ALREADY_EXISTS_ERROR" => Err(SuperTokensError::Generic(
            "Phone number already exists in tenant".to_string(),
        )),
        "THIRD_PARTY_USER_ALREADY_EXISTS_ERROR" => Err(SuperTokensError::Generic(
            "Third party user already exists in tenant".to_string(),
        )),
        "ASSOCIATION_NOT_ALLOWED_ERROR" => Err(SuperTokensError::Generic(
            "User association not allowed".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown associate user status: {}",
            associate_response.status
        ))),
    }
}

/// Disassociate a user from a tenant
pub async fn disassociate_user_from_tenant(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    recipe_user_id: impl Into<String>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!(
        "{}/recipe/multitenancy/tenant/user/remove",
        config.api_domain
    );

    let request_body = serde_json::json!({
        "tenantId": tenant_id.into(),
        "recipeUserId": recipe_user_id.into()
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
            let was_associated = response_json
                .get("wasAssociated")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            Ok(was_associated)
        }
        _ => Err(SuperTokensError::Generic(
            "Unknown disassociate user response".to_string(),
        )),
    }
}

/// Helper function to create default tenant configuration
pub fn create_default_tenant_config() -> TenantConfig {
    TenantConfig {
        first_factors: Some(vec![
            FirstFactors::EMAIL_PASSWORD.to_string(),
            FirstFactors::THIRD_PARTY.to_string(),
        ]),
        required_secondary_factors: None,
        core_config: None,
    }
}

/// Helper function to create tenant with PostgreSQL database
pub fn create_tenant_with_postgresql_config(postgresql_uri: impl Into<String>) -> TenantConfig {
    let mut core_config = HashMap::new();
    core_config.insert(
        "postgresql_connection_uri".to_string(),
        serde_json::Value::String(postgresql_uri.into()),
    );

    TenantConfig {
        first_factors: Some(vec![
            FirstFactors::EMAIL_PASSWORD.to_string(),
            FirstFactors::THIRD_PARTY.to_string(),
            FirstFactors::OTP_EMAIL.to_string(),
            FirstFactors::OTP_PHONE.to_string(),
        ]),
        required_secondary_factors: Some(vec![SecondFactors::TOTP.to_string()]),
        core_config: Some(core_config),
    }
}

/// Helper function to create enterprise tenant configuration
pub fn create_enterprise_tenant_config(
    enable_mfa: bool,
    custom_database_uri: Option<String>,
) -> TenantConfig {
    let mut core_config = HashMap::new();

    if let Some(db_uri) = custom_database_uri {
        core_config.insert(
            "postgresql_connection_uri".to_string(),
            serde_json::Value::String(db_uri),
        );
    }

    // Set longer token lifetimes for enterprise
    core_config.insert(
        "email_verification_token_lifetime".to_string(),
        serde_json::Value::Number(serde_json::Number::from(7200000)), // 2 hours
    );
    core_config.insert(
        "password_reset_token_lifetime".to_string(),
        serde_json::Value::Number(serde_json::Number::from(3600000)), // 1 hour
    );

    let required_secondary = if enable_mfa {
        Some(vec![SecondFactors::TOTP.to_string()])
    } else {
        None
    };

    TenantConfig {
        first_factors: Some(vec![
            FirstFactors::EMAIL_PASSWORD.to_string(),
            FirstFactors::THIRD_PARTY.to_string(),
        ]),
        required_secondary_factors: required_secondary,
        core_config: Some(core_config),
    }
}


