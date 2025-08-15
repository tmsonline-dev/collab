//! # SuperTokens SDK for Rust
//!
//! An unofficial, comprehensive Rust SDK for SuperTokens authentication and authorization.
//!
//! This SDK provides 100% feature parity with the Python SDK while offering the benefits
//! of Rust's type safety, performance, and memory safety.

pub mod config;
pub mod errors;
pub mod session;
pub mod utils;

// Authentication recipes
#[cfg(feature = "email-password")]
pub mod email_password;

#[cfg(feature = "passwordless")]
pub mod passwordless;

#[cfg(feature = "webauthn")]
pub mod webauthn;

#[cfg(feature = "oauth2")]
pub mod oauth2;

// Authorization & verification
#[cfg(feature = "user-roles")]
pub mod user_roles;

#[cfg(feature = "email-verification")]
pub mod email_verification;

#[cfg(feature = "multi-factor-auth")]
pub mod multi_factor_auth;

// Management & integration
#[cfg(feature = "account-linking")]
pub mod account_linking;

#[cfg(feature = "dashboard")]
pub mod dashboard;

#[cfg(feature = "multitenancy")]
pub mod multitenancy;

#[cfg(feature = "jwt")]
pub mod jwt;

// Framework middleware
#[cfg(feature = "axum-middleware")]
pub mod axum_middleware;

// #[cfg(feature = "actix-middleware")]
// pub mod actix_middleware;

pub use config::SuperTokensConfig;
pub use errors::{Result, SuperTokensError};
pub use session::{SessionContext, SessionInfo, refresh_session, revoke_session, verify_session};
pub use utils::create_http_client;

// Version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get enabled features
pub fn features() -> Vec<&'static str> {
    let mut enabled_features = Vec::new();

    #[cfg(feature = "email-password")]
    enabled_features.push("email-password");

    #[cfg(feature = "passwordless")]
    enabled_features.push("passwordless");

    #[cfg(feature = "webauthn")]
    enabled_features.push("webauthn");

    #[cfg(feature = "oauth2")]
    enabled_features.push("oauth2");

    #[cfg(feature = "user-roles")]
    enabled_features.push("user-roles");

    #[cfg(feature = "email-verification")]
    enabled_features.push("email-verification");

    #[cfg(feature = "multi-factor-auth")]
    enabled_features.push("multi-factor-auth");

    #[cfg(feature = "account-linking")]
    enabled_features.push("account-linking");

    #[cfg(feature = "dashboard")]
    enabled_features.push("dashboard");

    #[cfg(feature = "multitenancy")]
    enabled_features.push("multitenancy");

    #[cfg(feature = "jwt")]
    enabled_features.push("jwt");

    #[cfg(feature = "axum-middleware")]
    enabled_features.push("axum-middleware");

    enabled_features
}
