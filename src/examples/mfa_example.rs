use supertokens_sdk::{
    Result, SuperTokensConfig, email_password,
    multi_factor_auth::{
        create_totp_device, list_totp_devices, remove_totp_device, verify_totp_token,
    },
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize config
    let config = SuperTokensConfig::from_env()?;
    config.validate()?;

    println!("=== Multi-Factor Authentication Example ===");

    // 1. Sign up a user
    let user = email_password::sign_up(&config, "mfauser@example.com", "SecurePass123").await?;
    println!("✅ Signed up user: {}", user.id);

    // 2. Create a TOTP device for the user
    let (device_name, secret_key, qr_code) =
        create_totp_device(&config, &user.id, Some("Primary Device".to_string())).await?;
    println!("🔒 TOTP device created:");
    println!("   - Device: {}", device_name);
    println!("   - Secret: {}...", &secret_key[..16]);
    println!("   - QR: {}...", &qr_code[..50]);

    // 3. List all TOTP devices for the user
    let devices = list_totp_devices(&config, &user.id).await?;
    println!("📃 TOTP devices ({}):", devices.len());
    for d in &devices {
        println!(
            "   - {} (created at {})",
            d.device_name,
            d.period.unwrap_or(30)
        );
    }

    // 4. Simulate verifying TOTP token (replace with real token from authenticator)
    let fake_token = "123456";
    match verify_totp_token(&config, &user.id, fake_token, true).await {
        Ok(true) => println!("✅ TOTP verification succeeded"),
        Ok(false) => println!("⚠️ TOTP token was already verified earlier"),
        Err(e) => println!("❌ TOTP verification failed: {}", e),
    }

    // 5. Remove the TOTP device
    if let Some(device) = devices.first() {
        let removed = remove_totp_device(&config, &user.id, &device.device_name).await?;
        println!("🗑️ Removed device '{}': {}", device.device_name, removed);
    }

    println!("=== MFA Example Complete! ===");
    Ok(())
}
