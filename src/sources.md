# Rust lib (links of raw source code files from my github repo) for [SuperTokens](https://supertokens.com) authentication, authorization and user management in axum app

    "validation is required for the entire code base for its working as exptected with supertokens"

## [account_linking](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/account_linking.rs)

## [config](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/config.rs)

## [dashboard](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/dashboard.rs)

## [email_password](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/email_password.rs)

## [email_verification](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/email_verification.rs)

## [errors](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/errors.rs)

    - comprehensive error handling layer mapping SuperTokens errors to Axum responses
    - todo!("refined re-write of code expected as 'errors.rs' file")

## [jwt](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/jwt.rs)

## [lib](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/lib.rs)

## [multi_factor_auth](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/multi_factor_auth.rs)

## [multitenancy](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/multitenancy.rs)

## [oauth2](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/oauth2.rs)

## [session](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/session.rs)

## [user_roles](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/user_roles.rs)

## [utils](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/utils.rs)

## [web_authn](https://raw.githubusercontent.com/tmsonline-dev/collab/refs/heads/main/src/web_authn.rs)

## [axum_middleware](https://github.com/tmsonline-dev/collab/blob/main/src/axum_middleware.rs)

    - Clear distinction between `primaryUserId` and `recipeUserId` is needed.implement distinct Axum extractors for `PrimaryUser` and `RecipeUser` contexts

    - todo!("expected code re-write as 'axum_middleware.rs' ")

## Aim

- library serves as a bridge between the Axum web framework and SuperTokens, aiming to simplify the integration of robust user authentication, authorization and management in Rust application

### **🔐 Authentication Recipes**

- ✅ **Email/Password** - Traditional signup/signin with password reset
- ✅ **Passwordless** - Magic links and OTP (email/SMS) authentication  
- ✅ **WebAuthn/FIDO2** - Hardware keys, passkeys, and biometric authentication
- ✅ **OAuth2/Social Login** - Google, GitHub, Facebook, Microsoft, Apple, LinkedIn

### **🛡️ Authorization & Verification**

- ✅ **User Roles & Permissions** - Full RBAC (Role-Based Access Control)
- ✅ **Email Verification** - Required/Optional email verification flows
- ✅ **Multi-Factor Authentication** - TOTP, Email/SMS OTP, factor completion tracking

### **🔗 Management & Integration**

- ✅ **Account Linking** - Link multiple authentication methods per user
- ✅ **Dashboard APIs** - Programmatic user management and administration
- ✅ **Multi-tenancy** - Enterprise tenant management with isolated configurations
- ✅ **JWT/OpenID Connect** - Token creation, verification, and JWKS support

### **🌐 Framework Support**

- ✅ **Session Management** - Verify, refresh, revoke with automatic role loading
- ✅ **Axum Middleware** - Drop-in session verification and extraction.
