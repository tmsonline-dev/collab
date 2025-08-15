use supertokens_sdk::{
    FactorId, Result, config::SuperTokensConfig, email_password, email_verification,
    multi_factor_auth, user_roles,
};

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Complete SuperTokens Rust SDK Example ===");

    // Initialize configuration
    let config = SuperTokensConfig::from_env()?;
    config.validate()?;

    // Show enabled features
    println!("Enabled features: {:?}", supertokens_sdk::features());

    // 1. User Registration with Email/Password
    println!("\n1. Creating user with email/password...");
    let user = match email_password::sign_up(&config, "admin@company.com", "SecurePass123!").await {
        Ok(user) => user,
        Err(supertokens_sdk::SuperTokensError::EmailAlreadyExists) => {
            println!("User already exists, signing in...");
            email_password::sign_in(&config, "admin@company.com", "SecurePass123!").await?
        }
        Err(e) => return Err(e),
    };
    println!("✅ User created/found: {}", user.id);

    // 2. Set up User Roles (RBAC)
    println!("\n2. Setting up user roles and permissions...");

    // Create admin role with comprehensive permissions
    let admin_permissions = vec![
        "read:all".to_string(),
        "write:all".to_string(),
        "delete:all".to_string(),
        "admin:users".to_string(),
        "admin:system".to_string(),
        "mfa:manage".to_string(),
    ];

    user_roles::create_new_role_or_add_permissions(&config, "admin", admin_permissions).await?;
    user_roles::add_role_to_user(&config, "public", &user.id, "admin").await?;

    println!("✅ Admin role assigned to user");

    // Verify user permissions
    let user_roles_list = user_roles::get_roles_for_user(&config, "public", &user.id).await?;
    let has_admin_permission =
        user_roles::user_has_permission(&config, "public", &user.id, "admin:system").await?;
    println!("   - User roles: {:?}", user_roles_list);
    println!("   - Has admin:system permission: {}", has_admin_permission);

    // 3. Email Verification Flow
    println!("\n3. Email verification process...");

    // Check if email is already verified
    let is_verified = email_verification::is_email_verified(&config, &user.id, &user.email).await?;
    println!("   - Email verified status: {}", is_verified);

    if !is_verified {
        // Create verification token and simulate verification
        let verification_token = email_verification::create_email_verification_token(
            &config,
            "public",
            &user.id,
            &user.email,
        )
        .await?;
        println!(
            "   - Created verification token: {}",
            &verification_token[..20]
        ); // Show first 20 chars

        // Verify the email using the token
        let (verified_user_id, verified_email) =
            email_verification::verify_email_using_token(&config, "public", &verification_token)
                .await?;
        println!(
            "✅ Email verified: {} for user {}",
            verified_email, verified_user_id
        );
    } else {
        println!("✅ Email already verified");
    }

    // 4. Multi-Factor Authentication (MFA) Setup
    println!("\n4. Setting up Multi-Factor Authentication...");

    // Create TOTP device (like Google Authenticator)
    let (device_name, secret_key, qr_code) = multi_factor_auth::create_totp_device(
        &config,
        &user.id,
        Some("Primary Device".to_string()),
    )
    .await?;

    println!("✅ TOTP device created:");
    println!("   - Device: {}", device_name);
    println!("   - Secret: {}...", &secret_key[..16]); // Show first 16 chars
    println!("   - QR Code: {}...", &qr_code[..50]); // Show first 50 chars

    // List all TOTP devices
    let totp_devices = multi_factor_auth::list_totp_devices(&config, &user.id).await?;
    println!("   - Total TOTP devices: {}", totp_devices.len());

    // 5. Simulate complete authentication flow with MFA
    println!("\n5. Complete authentication flow simulation...");

    // First factor: email/password (already done above)
    println!("✅ First factor complete: email/password");

    // Second factor: TOTP (simulate with a mock token)
    // Note: In real usage, you'd get this from user's authenticator app
    let mock_totp_token = "123456"; // This would fail in real scenario
    match multi_factor_auth::verify_totp_token(&config, &user.id, mock_totp_token, true).await {
        Ok(_) => println!("✅ Second factor complete: TOTP"),
        Err(_) => println!("⚠️  Second factor simulation (expected to fail with mock token)"),
    }

    // 6. Advanced Role Management
    println!("\n6. Advanced role and permission management...");

    // Create additional roles
    let manager_permissions = vec![
        "read:all".to_string(),
        "write:own".to_string(),
        "manage:team".to_string(),
    ];
    user_roles::create_new_role_or_add_permissions(&config, "manager", manager_permissions).await?;

    let user_permissions = vec!["read:own".to_string(), "write:own".to_string()];
    user_roles::create_new_role_or_add_permissions(&config, "user", user_permissions).await?;

    // Show all roles in system
    let all_roles = user_roles::get_all_roles(&config).await?;
    println!("✅ All roles in system: {:?}", all_roles);

    // Show roles with specific permission
    let roles_with_read_all =
        user_roles::get_roles_that_have_permission(&config, "read:all").await?;
    println!("   - Roles with 'read:all': {:?}", roles_with_read_all);

    // 7. Session Simulation (with roles and permissions)
    println!("\n7. Session management with roles/permissions...");

    // In a real scenario, you'd have an actual access token from login
    println!("📝 Note: Session verification requires actual access token from SuperTokens Core");
    println!(
        "   - Session would include user roles: {:?}",
        user_roles_list
    );
    println!("   - Session would include MFA status and completed factors");
    println!("   - Framework middleware would automatically verify and inject this data");

    // 8. Security Audit Summary
    println!("\n8. Security Summary:");
    println!("✅ Email/Password: Strong password authentication");
    println!("✅ Email Verification: Email ownership confirmed");
    println!("✅ RBAC: Role-based access control configured");
    println!("✅ MFA Ready: TOTP device configured");
    println!("✅ PostgreSQL: Database backend supported");
    println!("✅ Type Safety: Compile-time error checking");

    println!("\n=== SuperTokens Rust SDK Demo Complete! ===");
    println!("🦀 Your authentication system is production-ready with:");
    println!("   - Multi-factor authentication");
    println!("   - Role-based authorization");
    println!("   - Email verification");
    println!("   - PostgreSQL/MySQL/SQLite support");
    println!("   - Type-safe Rust implementation");

    Ok(())
}
