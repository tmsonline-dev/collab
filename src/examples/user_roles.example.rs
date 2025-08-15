use supertokens_sdk::{Result, config::SuperTokensConfig, email_password, user_roles};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize SuperTokens configuration
    let config = SuperTokensConfig::from_env()?;
    config.validate()?;

    println!("=== SuperTokens User Roles Example ===");

    // Example: Create roles with permissions
    println!("\n1. Creating roles with permissions...");

    let admin_permissions = vec![
        "read:all".to_string(),
        "write:all".to_string(),
        "delete:all".to_string(),
        "admin:users".to_string(),
    ];

    let user_permissions = vec![
        "read:own".to_string(),
        "write:own".to_string(),
        "delete:own".to_string(),
    ];

    let moderator_permissions = vec![
        "read:all".to_string(),
        "write:own".to_string(),
        "moderate:content".to_string(),
    ];

    // Create roles
    let created_admin =
        user_roles::create_new_role_or_add_permissions(&config, "admin", admin_permissions).await?;
    println!("Admin role created: {}", created_admin);

    let created_user =
        user_roles::create_new_role_or_add_permissions(&config, "user", user_permissions).await?;
    println!("User role created: {}", created_user);

    let created_moderator =
        user_roles::create_new_role_or_add_permissions(&config, "moderator", moderator_permissions)
            .await?;
    println!("Moderator role created: {}", created_moderator);

    // Example: Create a user and assign roles
    println!("\n2. Creating user and assigning roles...");

    let user =
        match email_password::sign_up(&config, "admin@example.com", "securepassword123").await {
            Ok(user) => user,
            Err(supertokens_sdk::SuperTokensError::EmailAlreadyExists) => {
                // User already exists, sign them in to get user info
                email_password::sign_in(&config, "admin@example.com", "securepassword123").await?
            }
            Err(e) => return Err(e),
        };

    println!("User created/found: ID={}, Email={}", user.id, user.email);

    // Assign admin role to user (using "public" tenant)
    let tenant_id = "public";
    let role_added = user_roles::add_role_to_user(&config, tenant_id, &user.id, "admin").await?;
    println!("Admin role added to user: {}", role_added);

    // Also assign user role (users can have multiple roles)
    let user_role_added =
        user_roles::add_role_to_user(&config, tenant_id, &user.id, "user").await?;
    println!("User role added to user: {}", user_role_added);

    // Example: Get user's roles
    println!("\n3. Getting user's roles...");
    let user_roles_list = user_roles::get_roles_for_user(&config, tenant_id, &user.id).await?;
    println!("User {} has roles: {:?}", user.id, user_roles_list);

    // Example: Check if user has specific role
    println!("\n4. Checking user permissions...");
    let has_admin_role = user_roles::user_has_role(&config, tenant_id, &user.id, "admin").await?;
    println!("User has admin role: {}", has_admin_role);

    let has_delete_all_permission =
        user_roles::user_has_permission(&config, tenant_id, &user.id, "delete:all").await?;
    println!(
        "User has 'delete:all' permission: {}",
        has_delete_all_permission
    );

    let has_moderate_permission =
        user_roles::user_has_permission(&config, tenant_id, &user.id, "moderate:content").await?;
    println!(
        "User has 'moderate:content' permission: {}",
        has_moderate_permission
    );

    // Example: Get permissions for a role
    println!("\n5. Getting permissions for roles...");
    let admin_perms = user_roles::get_permissions_for_role(&config, "admin").await?;
    println!("Admin role permissions: {:?}", admin_perms);

    let moderator_perms = user_roles::get_permissions_for_role(&config, "moderator").await?;
    println!("Moderator role permissions: {:?}", moderator_perms);

    // Example: Get all users with admin role
    println!("\n6. Getting users with admin role...");
    let admin_users = user_roles::get_users_that_have_role(&config, tenant_id, "admin").await?;
    println!("Users with admin role: {:?}", admin_users);

    // Example: Get all roles
    println!("\n7. Getting all roles...");
    let all_roles = user_roles::get_all_roles(&config).await?;
    println!("All roles in system: {:?}", all_roles);

    // Example: Get roles that have specific permission
    println!("\n8. Getting roles with 'read:all' permission...");
    let roles_with_read_all =
        user_roles::get_roles_that_have_permission(&config, "read:all").await?;
    println!(
        "Roles with 'read:all' permission: {:?}",
        roles_with_read_all
    );

    // Example: Remove a permission from a role
    println!("\n9. Removing permission from role...");
    user_roles::remove_permissions_from_role(
        &config,
        "moderator",
        vec!["moderate:content".to_string()],
    )
    .await?;
    println!("Removed 'moderate:content' permission from moderator role");

    let updated_moderator_perms =
        user_roles::get_permissions_for_role(&config, "moderator").await?;
    println!(
        "Updated moderator permissions: {:?}",
        updated_moderator_perms
    );

    // Example: Remove role from user
    println!("\n10. Removing role from user...");
    let role_removed = user_roles::remove_user_role(&config, tenant_id, &user.id, "user").await?;
    println!("User role removed from user: {}", role_removed);

    let final_user_roles = user_roles::get_roles_for_user(&config, tenant_id, &user.id).await?;
    println!("User's final roles: {:?}", final_user_roles);

    println!("\n=== User Roles Example Complete ===");

    Ok(())
}
