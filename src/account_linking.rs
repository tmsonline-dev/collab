//! Account linking recipe for managing multiple login methods per user

use crate::{Result, config::SuperTokensConfig, errors::SuperTokensError};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Account linking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub email: Option<String>,
    #[serde(rename = "phoneNumber")]
    pub phone_number: Option<String>,
    #[serde(rename = "thirdParty")]
    pub third_party: Option<ThirdPartyInfo>,
}

/// Third party account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyInfo {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
}

/// Complete user information with all login methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedUser {
    pub id: String,
    #[serde(rename = "isPrimaryUser")]
    pub is_primary_user: bool,
    pub emails: Vec<String>,
    #[serde(rename = "phoneNumbers")]
    pub phone_numbers: Vec<String>,
    #[serde(rename = "loginMethods")]
    pub login_methods: Vec<LoginMethod>,
    #[serde(rename = "tenantIds")]
    pub tenant_ids: Vec<String>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    #[serde(rename = "timeJoined")]
    pub time_joined: DateTime<Utc>,
}

/// Individual login method for a user
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

/// Request to create a primary user
#[derive(Serialize)]
struct CreatePrimaryUserRequest {
    #[serde(rename = "recipeUserId")]
    recipe_user_id: String,
}

/// Response from creating a primary user
#[derive(Deserialize)]
struct CreatePrimaryUserResponse {
    status: String,
    user: Option<LinkedUser>,
    #[serde(rename = "wasAlreadyAPrimaryUser")]
    was_already_a_primary_user: Option<bool>,
}

/// Request to link accounts
#[derive(Serialize)]
struct LinkAccountsRequest {
    #[serde(rename = "recipeUserId")]
    recipe_user_id: String,
    #[serde(rename = "primaryUserId")]
    primary_user_id: String,
}

/// Response from linking accounts
#[derive(Deserialize)]
struct LinkAccountsResponse {
    status: String,
    user: Option<LinkedUser>,
    #[serde(rename = "accountsAlreadyLinked")]
    accounts_already_linked: Option<bool>,
}

/// Request to unlink account
#[derive(Serialize)]
struct UnlinkAccountRequest {
    #[serde(rename = "recipeUserId")]
    recipe_user_id: String,
}

/// Response from unlinking account
#[derive(Deserialize)]
struct UnlinkAccountResponse {
    status: String,
    #[serde(rename = "wasLinked")]
    was_linked: Option<bool>,
}

/// Request to check if accounts can be linked
#[derive(Serialize)]
struct CanLinkAccountsRequest {
    #[serde(rename = "recipeUserId")]
    recipe_user_id: String,
    #[serde(rename = "primaryUserId")]
    primary_user_id: String,
}

/// Response from checking if accounts can be linked
#[derive(Deserialize)]
struct CanLinkAccountsResponse {
    status: String,
    #[serde(rename = "accountsAlreadyLinked")]
    accounts_already_linked: Option<bool>,
}

/// Account linking result
#[derive(Debug, Clone)]
pub enum AccountLinkingResult {
    Ok {
        user: LinkedUser,
        was_already_linked: bool,
    },
    AccountInfoAlreadyAssociatedWithAnotherPrimaryUser,
    RecipeUserIdAlreadyLinkedWithPrimaryUser,
    InputUserIsNotAPrimaryUser,
}

/// Create primary user result
#[derive(Debug, Clone)]
pub enum CreatePrimaryUserResult {
    Ok {
        user: LinkedUser,
        was_already_primary: bool,
    },
    AccountInfoAlreadyAssociatedWithAnotherPrimaryUser,
    RecipeUserIdAlreadyLinkedWithPrimaryUser,
}

/// Create a primary user from a recipe user
pub async fn create_primary_user(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
) -> Result<CreatePrimaryUserResult> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/accountlinking/user/primary", config.api_domain);

    let request_body = CreatePrimaryUserRequest {
        recipe_user_id: recipe_user_id.into(),
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

    let create_response: CreatePrimaryUserResponse = response.json().await?;

    match create_response.status.as_str() {
        "OK" => {
            let user = create_response.user.ok_or_else(|| {
                SuperTokensError::Generic(
                    "Primary user creation succeeded but no user returned".to_string(),
                )
            })?;
            let was_already_primary = create_response.was_already_a_primary_user.unwrap_or(false);
            Ok(CreatePrimaryUserResult::Ok {
                user,
                was_already_primary,
            })
        }
        "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR" => {
            Ok(CreatePrimaryUserResult::AccountInfoAlreadyAssociatedWithAnotherPrimaryUser)
        }
        "RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR" => {
            Ok(CreatePrimaryUserResult::RecipeUserIdAlreadyLinkedWithPrimaryUser)
        }
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown create primary user status: {}",
            create_response.status
        ))),
    }
}

/// Link a recipe user to a primary user
pub async fn link_accounts(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
    primary_user_id: impl Into<String>,
) -> Result<AccountLinkingResult> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/accountlinking/user/link", config.api_domain);

    let request_body = LinkAccountsRequest {
        recipe_user_id: recipe_user_id.into(),
        primary_user_id: primary_user_id.into(),
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

    let link_response: LinkAccountsResponse = response.json().await?;

    match link_response.status.as_str() {
        "OK" => {
            let user = link_response.user.ok_or_else(|| {
                SuperTokensError::Generic(
                    "Account linking succeeded but no user returned".to_string(),
                )
            })?;
            let was_already_linked = link_response.accounts_already_linked.unwrap_or(false);
            Ok(AccountLinkingResult::Ok {
                user,
                was_already_linked,
            })
        }
        "ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR" => {
            Ok(AccountLinkingResult::AccountInfoAlreadyAssociatedWithAnotherPrimaryUser)
        }
        "INPUT_USER_IS_NOT_A_PRIMARY_USER" => Ok(AccountLinkingResult::InputUserIsNotAPrimaryUser),
        "RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR" => {
            Ok(AccountLinkingResult::RecipeUserIdAlreadyLinkedWithPrimaryUser)
        }
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown link accounts status: {}",
            link_response.status
        ))),
    }
}

/// Unlink a recipe user from its primary user
pub async fn unlink_account(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/accountlinking/user/unlink", config.api_domain);

    let request_body = UnlinkAccountRequest {
        recipe_user_id: recipe_user_id.into(),
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

    let unlink_response: UnlinkAccountResponse = response.json().await?;

    match unlink_response.status.as_str() {
        "OK" => Ok(unlink_response.was_linked.unwrap_or(false)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown unlink account status: {}",
            unlink_response.status
        ))),
    }
}

/// Check if two accounts can be linked
pub async fn can_link_accounts(
    config: &SuperTokensConfig,
    recipe_user_id: impl Into<String>,
    primary_user_id: impl Into<String>,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!(
        "{}/recipe/accountlinking/user/link/check",
        config.api_domain
    );

    let request_body = CanLinkAccountsRequest {
        recipe_user_id: recipe_user_id.into(),
        primary_user_id: primary_user_id.into(),
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

    let check_response: CanLinkAccountsResponse = response.json().await?;

    match check_response.status.as_str() {
        "OK" => Ok(!check_response.accounts_already_linked.unwrap_or(true)),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown can link accounts status: {}",
            check_response.status
        ))),
    }
}

/// Get user information by user ID (includes all linked accounts)
pub async fn get_user(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
) -> Result<Option<LinkedUser>> {
    let client = crate::create_http_client(config)?;
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

    let user: LinkedUser = response.json().await?;
    Ok(Some(user))
}

/// List users by account info (email, phone number, or third party)
pub async fn list_users_by_account_info(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    account_info: AccountInfo,
) -> Result<Vec<LinkedUser>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/users", config.api_domain);

    let mut query_params = vec![("tenantId", tenant_id.into())];

    if let Some(email) = account_info.email {
        query_params.push(("email", email));
    }
    if let Some(phone) = account_info.phone_number {
        query_params.push(("phoneNumber", phone));
    }
    if let Some(third_party) = account_info.third_party {
        query_params.push(("thirdPartyId", third_party.id));
        query_params.push(("thirdPartyUserId", third_party.user_id));
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

    let response_json: serde_json::Value = response.json().await?;

    if let Some(users) = response_json.get("users").and_then(|u| u.as_array()) {
        let linked_users: Result<Vec<LinkedUser>> = users
            .iter()
            .map(|u| serde_json::from_value(u.clone()).map_err(SuperTokensError::from))
            .collect();
        linked_users
    } else {
        Ok(vec![])
    }
}

/// Delete a user (all associated accounts)
pub async fn delete_user(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    remove_all_linked_accounts: bool,
) -> Result<bool> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/user/remove", config.api_domain);

    let request_body = serde_json::json!({
        "userId": user_id.into(),
        "removeAllLinkedAccounts": remove_all_linked_accounts
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
            let did_user_exist = response_json
                .get("didUserExist")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            Ok(did_user_exist)
        }
        _ => Err(SuperTokensError::Generic(
            "Unknown delete user response".to_string(),
        )),
    }
}

/// Helper function to get primary user ID from any recipe user ID
pub async fn get_primary_user_that_can_be_linked_to_recipe_user_id(
    config: &SuperTokensConfig,
    tenant_id: impl Into<String>,
    recipe_user_id: impl Into<String>,
) -> Result<Option<LinkedUser>> {
    let client = crate::create_http_client(config)?;
    let url = format!(
        "{}/recipe/accountlinking/user/primary/check",
        config.api_domain
    );

    let mut request = client.get(&url).query(&[
        ("tenantId", tenant_id.into()),
        ("recipeUserId", recipe_user_id.into()),
    ]);

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

    let response_json: serde_json::Value = response.json().await?;

    if let Some(user_data) = response_json.get("user") {
        let user: LinkedUser = serde_json::from_value(user_data.clone())?;
        Ok(Some(user))
    } else {
        Ok(None)
    }
}

/// Helper function to check if a user is a primary user
pub fn is_primary_user(user: &LinkedUser) -> bool {
    user.is_primary_user
}

/// Helper function to get all login methods for a user
pub fn get_login_methods_for_user(user: &LinkedUser) -> &[LoginMethod] {
    &user.login_methods
}

/// Helper function to find login method by recipe ID
pub fn find_login_method_by_recipe(user: &LinkedUser, recipe_id: &str) -> Option<&LoginMethod> {
    user.login_methods
        .iter()
        .find(|method| method.recipe_id == recipe_id)
}


