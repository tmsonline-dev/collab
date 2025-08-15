// examples/axum_integration.rs

use axum::{Router, extract::Extension, http::StatusCode, routing::get};
use std::net::SocketAddr;
use std::sync::Arc;
use supertokens_sdk::{
    Result, SuperTokensConfig, email_password,
    session::{SessionContext, require_session},
    user_roles,
};

async fn login_handler() -> String {
    // In a real app, you'd read credentials from request body
    // Here, just simulate login
    "Login endpoint - implement as needed".to_string()
}

async fn protected_handler(session: SessionContext) -> String {
    let user_id = &session.session_info.user_id;
    let roles = session.get_roles();
    let has_admin = session.has_role("admin");
    format!(
        "Hello {}! Roles: {:?}, is_admin: {}",
        user_id, roles, has_admin
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load config
    let config = SuperTokensConfig::from_env()?;
    config.validate()?;

    // Initialize Axum router
    let app = Router::new()
        .route("/login", get(login_handler))
        .route("/protected", get(protected_handler))
        .layer(Extension(Arc::new(config.clone())))
        .layer(require_session(config));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
