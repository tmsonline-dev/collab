// examples/basic_usage.rs

use supertokens_sdk::{Result, SuperTokensConfig, email_password, session, user_roles};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize SDK
    let config = SuperTokensConfig::from_env()?;
    config.validate()?;

    println!("=== Basic Usage Example ===");

    // 1. Email/password sign up
    let user = email_password::sign_up(&config, "basicuser@example.com", "BasicPass123").await?;
    println!("✅ User signed up: {}", user.id);

    // 2. Email/password sign in
    let user = email_password::sign_in(&config, "basicuser@example.com", "BasicPass123").await?;
    println!("🔑 User signed in: {}", user.id);

    // 3. Create role and assign
    user_roles::create_new_role_or_add_permissions(
        &config,
        "tester",
        vec!["read:basic".to_string()],
    )
    .await?;
    user_roles::add_role_to_user(&config, "public", &user.id, "tester").await?;
    println!("🎭 Assigned role 'tester' to user {}", user.id);

    // 4. Verify session (simulate using access token from sign in)
    // In real usage, capture access/refresh tokens from sign_in response
    // Here we skip actual token flow and demonstrate API signature:
    // let (session_info, _, _) = session::refresh_session(&config, "refresh_token").await?;

    println!("=== Basic Usage Example Complete ===");
    Ok(())
}
