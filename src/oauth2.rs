//! OAuth2 social authentication recipe - COMPLETE VERSION

use crate::{
    Result, config::SuperTokensConfig, errors::SuperTokensError, ,
};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// OAuth2 provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Provider {
    pub id: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub user_info_endpoint: String,
    pub scope: Vec<String>,
    pub additional_params: HashMap<String, String>,
}

/// OAuth2 user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub time_joined: DateTime<Utc>,
    pub third_party: ThirdPartyInfo,
}

/// Third party provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThirdPartyInfo {
    pub id: String,
    pub user_id: String,
}

/// Authorization URL request
#[derive(Serialize)]
struct AuthorizationUrlRequest {
    #[serde(rename = "thirdPartyId")]
    third_party_id: String,
    #[serde(rename = "redirectURIOnProviderDashboard")]
    redirect_uri: String,
}

/// Authorization URL response
#[derive(Deserialize)]
struct AuthorizationUrlResponse {
    status: String,
    #[serde(rename = "urlWithQueryParams")]
    url_with_query_params: Option<String>,
    #[serde(rename = "pkceCodeVerifier")]
    pkce_code_verifier: Option<String>,
}

/// Sign in/up with OAuth2 request
#[derive(Serialize)]
struct OAuth2SignInUpRequest {
    #[serde(rename = "thirdPartyId")]
    third_party_id: String,
    #[serde(rename = "redirectURIOnProviderDashboard")]
    redirect_uri: String,
    code: String,
    state: Option<String>,
    #[serde(rename = "pkceCodeVerifier")]
    pkce_code_verifier: Option<String>,
}

/// Sign in/up with OAuth2 response
#[derive(Deserialize)]
struct OAuth2SignInUpResponse {
    status: String,
    user: Option<OAuth2User>,
    #[serde(rename = "createdNewUser")]
    created_new_user: Option<bool>,
}

/// Built-in OAuth2 providers
pub struct OAuth2Providers;

impl OAuth2Providers {
    /// Google OAuth2 provider
    pub fn google(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuth2Provider {
        OAuth2Provider {
            id: "google".to_string(),
            name: "Google".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            user_info_endpoint: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scope: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            additional_params: HashMap::new(),
        }
    }

    /// GitHub OAuth2 provider
    pub fn github(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuth2Provider {
        OAuth2Provider {
            id: "github".to_string(),
            name: "GitHub".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorization_endpoint: "https://github.com/login/oauth/authorize".to_string(),
            token_endpoint: "https://github.com/login/oauth/access_token".to_string(),
            user_info_endpoint: "https://api.github.com/user".to_string(),
            scope: vec!["user:email".to_string()],
            additional_params: HashMap::new(),
        }
    }

    /// Facebook OAuth2 provider
    pub fn facebook(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuth2Provider {
        OAuth2Provider {
            id: "facebook".to_string(),
            name: "Facebook".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorization_endpoint: "https://www.facebook.com/v18.0/dialog/oauth".to_string(),
            token_endpoint: "https://graph.facebook.com/v18.0/oauth/access_token".to_string(),
            user_info_endpoint: "https://graph.facebook.com/me".to_string(),
            scope: vec!["email".to_string()],
            additional_params: [("fields".to_string(), "id,name,email".to_string())]
                .iter()
                .cloned()
                .collect(),
        }
    }

    /// Microsoft OAuth2 provider
    pub fn microsoft(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuth2Provider {
        OAuth2Provider {
            id: "microsoft".to_string(),
            name: "Microsoft".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorization_endpoint:
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
            token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token"
                .to_string(),
            user_info_endpoint: "https://graph.microsoft.com/v1.0/me".to_string(),
            scope: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            additional_params: HashMap::new(),
        }
    }

    /// Apple OAuth2 provider
    pub fn apple(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
        OAuth2Provider {
            id: "apple".to_string(),
            name: "Apple".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorization_endpoint: "https://appleid.apple.com/auth/authorize".to_string(),
            token_endpoint: "https://appleid.apple.com/auth/token".to_string(),
            user_info_endpoint: "https://appleid.apple.com/auth/userinfo".to_string(),
            scope: vec![
                "openid".to_string(),
                "email".to_string(),
                "name".to_string(),
            ],
            additional_params: [("response_mode".to_string(), "form_post".to_string())]
                .iter()
                .cloned()
                .collect(),
        }
    }

    /// LinkedIn OAuth2 provider
    pub fn linkedin(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuth2Provider {
        OAuth2Provider {
            id: "linkedin".to_string(),
            name: "LinkedIn".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorization_endpoint: "https://www.linkedin.com/oauth/v2/authorization".to_string(),
            token_endpoint: "https://www.linkedin.com/oauth/v2/accessToken".to_string(),
            user_info_endpoint: "https://api.linkedin.com/v2/people/~".to_string(),
            scope: vec!["r_liteprofile".to_string(), "r_emailaddress".to_string()],
            additional_params: HashMap::new(),
        }
    }
}

/// Enhanced error variants for OAuth2
impl SuperTokensError {
    pub fn no_email_given_by_provider() -> Self {
        SuperTokensError::OAuth2Error("No email given by OAuth2 provider".to_string())
    }

    pub fn sign_up_not_allowed() -> Self {
        SuperTokensError::OAuth2Error("Sign up not allowed for this OAuth2 provider".to_string())
    }
}

/// Get OAuth2 authorization URL with PKCE verifier
pub async fn get_authorization_url(
    config: &SuperTokensConfig,
    provider_id: impl Into<String>,
    redirect_uri: impl Into<String>,
) -> Result<(String, String)> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/oauth2/authorization-url", config.api_domain);

    let request_body = AuthorizationUrlRequest {
        third_party_id: provider_id.into(),
        redirect_uri: redirect_uri.into(),
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

    let auth_response: AuthorizationUrlResponse = response.json().await?;

    match auth_response.status.as_str() {
        "OK" => {
            let url = auth_response.url_with_query_params.ok_or_else(|| {
                SuperTokensError::oauth2_error("Authorization URL succeeded but no URL returned")
            })?;
            let verifier = auth_response
                .pkce_code_verifier
                .ok_or_else(|| SuperTokensError::oauth2_error("PKCE verifier missing"))?;
            Ok((url, verifier))
        }
        _ => Err(SuperTokensError::oauth2_error(format!(
            "Unknown authorization URL status: {}",
            auth_response.status
        ))),
    }
}

/// Complete OAuth2 sign in/up with authorization code
pub async fn sign_in_up_with_code(
    config: &SuperTokensConfig,
    provider_id: impl Into<String>,
    redirect_uri: impl Into<String>,
    code: impl Into<String>,
    state: Option<String>,
    pkce_code_verifier: Option<String>,
) -> Result<(OAuth2User, bool)> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/oauth2/signin-up", config.api_domain);

    let request_body = OAuth2SignInUpRequest {
        third_party_id: provider_id.into(),
        redirect_uri: redirect_uri.into(),
        code: code.into(),
        state,
        pkce_code_verifier,
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

    let signin_response: OAuth2SignInUpResponse = response.json().await?;

    match signin_response.status.as_str() {
        "OK" => {
            let user = signin_response.user.ok_or_else(|| {
                SuperTokensError::oauth2_error("OAuth2 sign in succeeded but no user returned")
            })?;
            let created_new_user = signin_response.created_new_user.unwrap_or(false);
            Ok((user, created_new_user))
        }
        "NO_EMAIL_GIVEN_BY_PROVIDER" => Err(SuperTokensError::no_email_given_by_provider()),
        "SIGN_UP_NOT_ALLOWED" => Err(SuperTokensError::sign_up_not_allowed()),
        _ => Err(SuperTokensError::oauth2_error(format!(
            "Unknown OAuth2 sign in status: {}",
            signin_response.status
        ))),
    }
}

/// Get user by third party ID
pub async fn get_user_by_third_party_id(
    config: &SuperTokensConfig,
    provider_id: impl Into<String>,
    third_party_user_id: impl Into<String>,
) -> Result<Option<OAuth2User>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/oauth2/user", config.api_domain);

    let mut request = client.get(&url).query(&[
        ("thirdPartyId", provider_id.into()),
        ("thirdPartyUserId", third_party_user_id.into()),
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

    let user: OAuth2User = response.json().await?;
    Ok(Some(user))
}

/// Get OAuth2 user by email
pub async fn get_user_by_email(
    config: &SuperTokensConfig,
    tenant_id: Option<String>,
    email: impl Into<String>,
) -> Result<Option<OAuth2User>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/oauth2/user/email", config.api_domain);

    let tenant_id = tenant_id.unwrap_or_else(|| "public".to_string());
    let mut request = client
        .get(&url)
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

    let user: OAuth2User = response.json().await?;
    Ok(Some(user))
}

/// List all configured OAuth2 providers
pub async fn get_providers(config: &SuperTokensConfig) -> Result<Vec<OAuth2Provider>> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/oauth2/providers", config.api_domain);

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

    let providers: Vec<OAuth2Provider> = response.json().await?;
    Ok(providers)
}

/// Unlink third party account from user
pub async fn unlink_account(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    provider_id: impl Into<String>,
) -> Result<()> {
    let client = crate::create_http_client(config)?;
    let url = format!("{}/recipe/oauth2/unlink", config.api_domain);

    let request_body = serde_json::json!({
        "userId": user_id.into(),
        "thirdPartyId": provider_id.into()
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

/// Build authorization URL manually (client-side helper)
pub fn build_authorization_url(
    provider: &OAuth2Provider,
    redirect_uri: &str,
    state: Option<&str>,
) -> Result<String> {
    let mut url = Url::parse(&provider.authorization_endpoint).map_err(|e| {
        SuperTokensError::oauth2_error(format!("Invalid authorization endpoint: {}", e))
    })?;

    {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs.append_pair("client_id", &provider.client_id);
        query_pairs.append_pair("redirect_uri", redirect_uri);
        query_pairs.append_pair("response_type", "code");
        query_pairs.append_pair("scope", &provider.scope.join(" "));

        if let Some(state) = state {
            query_pairs.append_pair("state", state);
        }

        for (key, value) in &provider.additional_params {
            query_pairs.append_pair(key, value);
        }
    }

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::create_test_config;

    #[test]
    fn test_provider_creation() {
        let google = OAuth2Providers::google("client_id", "client_secret");
        assert_eq!(google.id, "google");
        assert_eq!(google.name, "Google");
        assert!(google.scope.contains(&"email".to_string()));
    }

    #[test]
    fn test_build_authorization_url() {
        let provider = OAuth2Providers::github("test_id", "test_secret");
        let url = build_authorization_url(
            &provider,
            "http://localhost:3000/callback",
            Some("state123"),
        )
        .unwrap();

        assert!(url.contains("client_id=test_id"));
        assert!(url.contains("redirect_uri=http%3A//localhost%3A3000/callback"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("scope=user%3Aemail"));
    }

    #[tokio::test]
    #[ignore] // Requires running SuperTokens Core
    async fn test_oauth2_flow() {
        let config = create_test_config();

        // Test get providers
        // let providers = get_providers(&config).await;
        // assert!(providers.is_ok());

        // Test authorization URL generation
        // let (url, verifier) = get_authorization_url(&config, "google", "http://localhost:3000/callback").await;
        // assert!(url.is_ok());
        // assert!(verifier.is_ok());
    }
}
