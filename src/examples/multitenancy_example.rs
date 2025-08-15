use supertokens_sdk::{
    Result, SuperTokensConfig, email_password,
    multi_factor_auth::{create_totp_device, list_totp_devices, verify_totp_token},
    multitenancy,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize configuration
    let config = SuperTokensConfig::from_env()?;
    config.validate()?;

    println!("=== Multi-tenancy Example ===");

    // 1. Create a new tenant with PostgreSQL config
    let tenant_config =
        multitenancy::create_tenant_with_postgresql_config("postgresql://localhost:5432/tenant_db");
    let created =
        multitenancy::create_or_update_tenant(&config, "enterprise-client", tenant_config).await?;
    println!(
        "✅ Tenant 'enterprise-client' created or updated: {}",
        created
    );

    // 2. List all tenants
    let tenants = multitenancy::list_all_tenants(&config).await?;
    println!("🔍 All tenants:");
    for t in &tenants {
        println!("   - {}", t.tenant_id);
    }

    // 3. Create a user via email/password
    let user = email_password::sign_up(&config, "tenantuser@example.com", "Pass1234!").await?;
    println!("✅ Created user: {}", user.id);

    // 4. Associate user to tenant
    let associated =
        multitenancy::associate_user_to_tenant(&config, "enterprise-client", &user.id).await?;
    println!("🔗 User associated to tenant: {}", associated);

    // 5. Configure MFA requirement per tenant
    let provider_config = multitenancy::ProviderConfig {
        third_party_id: "google".to_string(),
        name: Some("Google".to_string()),
        client_id: "client_id".to_string(),
        client_secret: Some("secret".to_string()),
        ..Default::default()
    };
    let mfa_added = multitenancy::create_or_update_third_party_config(
        &config,
        "enterprise-client",
        provider_config,
        None,
    )
    .await?;
    println!("🔧 Third-party config for tenant updated: {}", mfa_added);

    // 6. Get tenant info
    if let Some(tenant) = multitenancy::get_tenant(&config, "enterprise-client").await? {
        println!("📋 Tenant 'enterprise-client' config:");
        println!("   - firstFactors: {:?}", tenant.first_factors);
        println!(
            "   - requiredSecondaryFactors: {:?}",
            tenant.required_secondary_factors
        );
    }

    // 7. Disassociate user from tenant
    let disassociated =
        multitenancy::disassociate_user_from_tenant(&config, "enterprise-client", &user.id).await?;
    println!("🔗 User disassociated from tenant: {}", disassociated);

    // 8. Delete tenant
    let deleted = multitenancy::delete_tenant(&config, "enterprise-client").await?;
    println!("❌ Tenant 'enterprise-client' deleted: {}", deleted);

    println!("=== Multi-tenancy Example Complete! ===");
    Ok(())
}
