use supertokens_sdk::{
    PublicKeyCredentialAssertion, Result, SuperTokensConfig, ThirdPartyInfo, account_linking,
    email_password,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize configuration
    let config = SuperTokensConfig::from_env()?;
    config.validate()?;

    println!("=== Account Linking Example ===");

    // 1. Create base user via email/password
    let user = email_password::sign_up(&config, "linkuser@example.com", "MySecret123!").await?;
    println!("✅ Signed up user: {}", user.id);

    // 2. Simulate third-party user info
    // In reality, you'd get this from OAuth2 or WebAuthn flows
    let third_party_info = ThirdPartyInfo {
        id: "github".to_string(),
        user_id: "gh-user-123".to_string(),
    };

    // 3. Create a primary user if not exists (makes base user primary)
    let primary_result = account_linking::create_primary_user(&config, &user.id).await?;
    match primary_result {
        CreatePrimaryUserResult::Ok {
            was_already_primary,
            user,
        } => {
            if was_already_primary {
                println!("🔗 User {} was already primary", user.id);
            } else {
                println!("🔗 User {} marked as primary", user.id);
            }
        }
        CreatePrimaryUserResult::AccountInfoAlreadyAssociatedWithAnotherPrimaryUser => {
            println!("❌ Account info already linked to another primary user");
        }
        CreatePrimaryUserResult::RecipeUserIdAlreadyLinkedWithPrimaryUser => {
            println!("❌ Recipe user ID already linked to a primary user");
        }
    }

    // 4. Link a second recipe user (simulate after sign-in via other recipe)
    let link_result = account_linking::link_accounts(
        &config,
        "gh-user-123", // third-party recipe user ID
        &user.id,
    )
    .await?;
    match link_result {
        AccountLinkingResult::Ok {
            was_already_linked,
            user,
        } => {
            if was_already_linked {
                println!("🔗 Accounts already linked for user {}", user.id);
            } else {
                println!("🔗 Linked accounts for primary user {}", user.id);
            }
        }
        AccountLinkingResult::AccountInfoAlreadyAssociatedWithAnotherPrimaryUser => {
            println!("❌ Credential already linked to another primary user");
        }
        AccountLinkingResult::InputUserIsNotAPrimaryUser => {
            println!("❌ Input user is not a primary user");
        }
        AccountLinkingResult::RecipeUserIdAlreadyLinkedWithPrimaryUser => {
            println!("❌ Recipe user ID already linked with primary user");
        }
    }

    // 5. List all linked users for primary user
    if let Some(linked) = account_linking::get_user(&config, &user.id).await? {
        println!("🔗 Primary user {} info:", linked.id);
        for method in account_linking::get_login_methods_for_user(&linked) {
            println!("   - {:?}", method.recipe_id);
        }
    }

    // 6. Unlink the third-party account
    let unlinked = account_linking::unlink_account(&config, "gh-user-123").await?;
    println!("🔗 Unlink result: {}", unlinked);

    println!("=== Account Linking Example Complete! ===");
    Ok(())
}
