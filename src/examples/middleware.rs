//! Axum middleware for SuperTokens session verification and user extraction
//!
//! This module provides drop-in middleware for Axum applications to:
//! - Verify SuperTokens sessions automatically
//! - Extract user information from sessions
//! - Handle session refresh automatically
//! - Provide user data as extractors in handlers

use crate::{
    config::SuperTokensConfig,
    errors::{Result, SuperTokensError},
    session::{SessionContext, SessionInfo, refresh_session, verify_session},
};

use axum::{
    Extension,
    extract::{FromRequestParts, Request},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_cookies::Cookies;

/// User information extracted from SuperTokens session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperTokensUser {
    pub user_id: String,
    pub session_handle: String,
    pub access_token_payload: serde_json::Value,
    pub user_data_in_database: serde_json::Value,
    pub time_created: chrono::DateTime<chrono::Utc>,
    pub expiry: chrono::DateTime<chrono::Utc>,
    pub tenant_id: Option<String>,

    #[cfg(feature = "user-roles")]
    pub roles: Option<Vec<String>>,

    #[cfg(feature = "user-roles")]
    pub permissions: Option<Vec<String>>,
}

impl From<SessionInfo> for SuperTokensUser {
    fn from(session: SessionInfo) -> Self {
        Self {
            user_id: session.user_id,
            session_handle: session.session_handle,
            access_token_payload: session.access_token_payload,
            user_data_in_database: session.user_data_in_database,
            time_created: session.time_created,
            expiry: session.expiry,
            tenant_id: Some("public".to_string()), // Default tenant

            #[cfg(feature = "user-roles")]
            roles: session.roles,

            #[cfg(feature = "user-roles")]
            permissions: session.permissions,
        }
    }
}

/// Session data extracted from SuperTokens
#[derive(Debug, Clone)]
pub struct SuperTokensSession {
    pub user: SuperTokensUser,
    pub context: SessionContext,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub anti_csrf_token: Option<String>,
}

/// Optional user extractor - doesn't fail if no session exists
#[derive(Debug, Clone)]
pub struct OptionalSuperTokensUser(pub Option<SuperTokensUser>);

/// Required user extractor - returns 401 if no valid session
#[derive(Debug, Clone)]
pub struct RequiredSuperTokensUser(pub SuperTokensUser);

/// Session extractor that provides full session information
#[derive(Debug, Clone)]
pub struct SuperTokensSessionExtractor(pub SuperTokensSession);

/// Middleware configuration
#[derive(Debug, Clone)]
pub struct SuperTokensMiddlewareConfig {
    pub config: Arc<SuperTokensConfig>,
    pub require_auth: bool,
    pub require_email_verification: bool,
    pub required_roles: Option<Vec<String>>,
    pub required_permissions: Option<Vec<String>>,
}

impl SuperTokensMiddlewareConfig {
    pub fn new(config: SuperTokensConfig) -> Self {
        Self {
            config: Arc::new(config),
            require_auth: false,
            require_email_verification: false,
            required_roles: None,
            required_permissions: None,
        }
    }

    pub fn require_auth(mut self) -> Self {
        self.require_auth = true;
        self
    }

    pub fn require_email_verification(mut self) -> Self {
        self.require_email_verification = true;
        self
    }

    pub fn require_roles(mut self, roles: Vec<String>) -> Self {
        self.required_roles = Some(roles);
        self
    }

    pub fn require_permissions(mut self, permissions: Vec<String>) -> Self {
        self.required_permissions = Some(permissions);
        self
    }
}

/// Main middleware function for SuperTokens session verification
pub async fn supertokens_middleware(
    cookies: Cookies,
    Extension(config): Extension<SuperTokensMiddlewareConfig>,
    mut req: Request,
    next: Next,
) -> Result<Response> {
    let session_data = extract_session_from_request(&cookies, req.headers(), &config).await?;

    // Insert session data into request extensions
    if let Some(session) = session_data {
        req.extensions_mut()
            .insert(OptionalSuperTokensUser(Some(session.user.clone())));
        req.extensions_mut()
            .insert(SuperTokensSessionExtractor(session));
    } else {
        req.extensions_mut().insert(OptionalSuperTokensUser(None));

        // If auth is required but no session exists, return 401
        if config.require_auth {
            return Err(SuperTokensError::SessionExpired);
        }
    }

    let response = next.run(req).await;
    Ok(response)
}

/// Extract session information from request
async fn extract_session_from_request(
    cookies: &Cookies,
    headers: &HeaderMap,
    config: &SuperTokensMiddlewareConfig,
) -> Result<Option<SuperTokensSession>> {
    // Try to get access token from cookies first
    let access_token = cookies
        .get("sAccessToken")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            // Fallback to Authorization header
            headers
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
                .map(|token| token.to_string())
        });

    let access_token = match access_token {
        Some(token) => token,
        None => return Ok(None), // No token found
    };

    // Get refresh token from cookies
    let refresh_token = cookies
        .get("sRefreshToken")
        .map(|cookie| cookie.value().to_string());

    // Get anti-CSRF token from headers
    let anti_csrf_token = headers
        .get("anti-csrf")
        .and_then(|h| h.to_str().ok())
        .map(|token| token.to_string());

    // Verify the session using the correct function signature
    let session_info = match verify_session(&config.config, &access_token).await {
        Ok(session) => session,
        Err(SuperTokensError::InvalidToken(_)) => {
            // Try to refresh if we have a refresh token
            if let Some(ref_token) = &refresh_token {
                let refresh_result = refresh_session(&config.config, ref_token).await?;
                refresh_result.session
            } else {
                return Err(SuperTokensError::SessionExpired);
            }
        }
        Err(e) => return Err(e),
    };

    // Convert SessionInfo to SuperTokensUser
    let user = SuperTokensUser::from(session_info.clone());

    // Validate email verification if required
    if config.require_email_verification {
        let email_verified = user
            .access_token_payload
            .get("emailVerified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !email_verified {
            return Err(SuperTokensError::Generic(
                "Email verification required".to_string(),
            ));
        }
    }

    // Validate roles if required
    #[cfg(feature = "user-roles")]
    if let Some(required_roles) = &config.required_roles {
        if let Some(user_roles) = &user.roles {
            if !required_roles.iter().any(|role| user_roles.contains(role)) {
                return Err(SuperTokensError::Generic("Insufficient roles".to_string()));
            }
        } else {
            return Err(SuperTokensError::Generic(
                "No roles found for user".to_string(),
            ));
        }
    }

    // Validate permissions if required
    #[cfg(feature = "user-roles")]
    if let Some(required_permissions) = &config.required_permissions {
        if let Some(user_permissions) = &user.permissions {
            if !required_permissions
                .iter()
                .any(|perm| user_permissions.contains(perm))
            {
                return Err(SuperTokensError::Generic(
                    "Insufficient permissions".to_string(),
                ));
            }
        } else {
            return Err(SuperTokensError::Generic(
                "No permissions found for user".to_string(),
            ));
        }
    }

    let session_context = SessionContext::new(session_info);

    Ok(Some(SuperTokensSession {
        user,
        context: session_context,
        access_token,
        refresh_token,
        anti_csrf_token,
    }))
}

/// Implement FromRequestParts for OptionalSuperTokensUser
impl<S: Send + Sync> FromRequestParts<S> for OptionalSuperTokensUser {
    type Rejection = ();

    #[inline]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<OptionalSuperTokensUser>()
            .cloned()
            .unwrap_or(OptionalSuperTokensUser(None)))
    }
}

/// Implement FromRequestParts for RequiredSuperTokensUser
impl<S: Send + Sync> FromRequestParts<S> for RequiredSuperTokensUser {
    type Rejection = SuperTokensError;

    #[inline]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        let optional_user = parts
            .extensions
            .get::<OptionalSuperTokensUser>()
            .cloned()
            .unwrap_or(OptionalSuperTokensUser(None));

        match optional_user.0 {
            Some(user) => Ok(RequiredSuperTokensUser(user)),
            None => Err(SuperTokensError::SessionExpired),
        }
    }
}

/// Implement FromRequestParts for SuperTokensSessionExtractor
impl<S: Send + Sync> FromRequestParts<S> for SuperTokensSessionExtractor {
    type Rejection = SuperTokensError;

    #[inline]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<SuperTokensSessionExtractor>()
            .cloned()
            .ok_or(SuperTokensError::SessionExpired)
    }
}

/// Implement IntoResponse for SuperTokensError to handle middleware errors
impl IntoResponse for SuperTokensError {
    fn into_response(self) -> Response {
        let status_code = match self {
            SuperTokensError::SessionExpired
            | SuperTokensError::InvalidToken(_)
            | SuperTokensError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            SuperTokensError::UserNotFound => StatusCode::NOT_FOUND,
            SuperTokensError::EmailAlreadyExists | SuperTokensError::PhoneNumberAlreadyExists => {
                StatusCode::CONFLICT
            }
            SuperTokensError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            SuperTokensError::InvalidVerificationCode
            | SuperTokensError::PasswordPolicyError(_) => StatusCode::BAD_REQUEST,
            SuperTokensError::TooManyAttempts => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let error_body = self.to_json();

        (status_code, axum::Json(error_body)).into_response()
    }
}

/// Middleware to require authentication
pub async fn require_auth_middleware(
    Extension(user): Extension<OptionalSuperTokensUser>,
    req: Request,
    next: Next,
) -> Result<Response> {
    match user.0 {
        Some(_) => Ok(next.run(req).await),
        None => Err(SuperTokensError::SessionExpired),
    }
}

/// Middleware to require specific roles
#[cfg(feature = "user-roles")]
pub fn require_roles_middleware(
    roles: Vec<String>,
) -> impl Fn(
    Extension<OptionalSuperTokensUser>,
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send>>
+ Clone {
    move |Extension(user): Extension<OptionalSuperTokensUser>, req: Request, next: Next| {
        let required_roles = roles.clone();
        Box::pin(async move {
            match user.0 {
                Some(user) => {
                    if let Some(user_roles) = &user.roles {
                        if required_roles.iter().any(|role| user_roles.contains(role)) {
                            Ok(next.run(req).await)
                        } else {
                            Err(SuperTokensError::Generic("Insufficient roles".to_string()))
                        }
                    } else {
                        Err(SuperTokensError::Generic("No roles found".to_string()))
                    }
                }
                None => Err(SuperTokensError::SessionExpired),
            }
        })
    }
}

/// Middleware to require email verification
pub async fn require_email_verification_middleware(
    Extension(user): Extension<OptionalSuperTokensUser>,
    req: Request,
    next: Next,
) -> Result<Response> {
    match user.0 {
        Some(user) => {
            let email_verified = user
                .access_token_payload
                .get("emailVerified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if email_verified {
                Ok(next.run(req).await)
            } else {
                Err(SuperTokensError::Generic(
                    "Email verification required".to_string(),
                ))
            }
        }
        None => Err(SuperTokensError::SessionExpired),
    }
}

/// Helper function to create a middleware layer
pub fn supertokens_layer(
    config: SuperTokensMiddlewareConfig,
) -> axum::middleware::FromFnLayer<
    impl Fn(
        Request,
        Next,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<Response<axum::body::Body>, SuperTokensError>,
                > + Send,
        >,
    > + Clone
    + Send,
    (),
    Response<axum::body::Body>,
> {
    let config = Arc::new(config);
    axum::middleware::from_fn(
        move |req: Request,
              next: Next|
              -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<Response<axum::body::Body>, SuperTokensError>,
                    > + Send,
            >,
        > {
            let config = Arc::clone(&config);
            Box::pin(async move {
                let cookies = req
                    .extensions()
                    .get::<Cookies>()
                    .cloned()
                    .expect("CookieManagerLayer required");
                supertokens_middleware(cookies, Extension((*config).clone()), req, next).await
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        extract::Request,
        http::{Method, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;
    use tower_cookies::CookieManagerLayer;

    fn create_test_config() -> SuperTokensConfig {
        SuperTokensConfig {
            app_name: "test".to_string(),
            api_domain: "http://localhost:3567".to_string(),
            website_domain: "http://localhost:3000".to_string(),
            api_key: None,
            options: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_optional_user_extractor() {
        let app = Router::new()
            .route(
                "/",
                get(
                    |OptionalSuperTokensUser(user): OptionalSuperTokensUser| async move {
                        match user {
                            Some(u) => format!("Hello, {}!", u.user_id),
                            None => "Hello, anonymous!".to_string(),
                        }
                    },
                ),
            )
            .layer(CookieManagerLayer::new());

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_middleware_config_builder() {
        let config = create_test_config();
        let middleware_config = SuperTokensMiddlewareConfig::new(config)
            .require_auth()
            .require_email_verification()
            .require_roles(vec!["admin".to_string(), "user".to_string()]);

        assert!(middleware_config.require_auth);
        assert!(middleware_config.require_email_verification);
        assert!(middleware_config.required_roles.is_some());
        assert_eq!(
            middleware_config.required_roles.unwrap(),
            vec!["admin".to_string(), "user".to_string()]
        );
    }

    #[test]
    fn test_supertokens_error_to_response() {
        let error = SuperTokensError::SessionExpired;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let error = SuperTokensError::UserNotFound;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let error = SuperTokensError::EmailAlreadyExists;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_user_conversion_from_session_info() {
        let session_info = SessionInfo {
            session_handle: "test_handle".to_string(),
            user_id: "test_user".to_string(),
            access_token_payload: serde_json::json!({"email": "[email protected]"}),
            user_data_in_database: serde_json::json!({}),
            time_created: chrono::Utc::now(),
            expiry: chrono::Utc::now() + chrono::Duration::hours(1),
            #[cfg(feature = "user-roles")]
            roles: Some(vec!["admin".to_string()]),
            #[cfg(feature = "user-roles")]
            permissions: Some(vec!["read:all".to_string()]),
        };

        let user = SuperTokensUser::from(session_info);
        assert_eq!(user.user_id, "test_user");
        assert_eq!(user.session_handle, "test_handle");
        assert_eq!(user.tenant_id, Some("public".to_string()));

        #[cfg(feature = "user-roles")]
        {
            assert_eq!(user.roles, Some(vec!["admin".to_string()]));
            assert_eq!(user.permissions, Some(vec!["read:all".to_string()]));
        }
    }
}
