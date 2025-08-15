//! JWT/OpenID Connect recipe for token creation and verification

use crate::{
    Result, config::SuperTokensConfig, errors::SuperTokensError, utils::create_http_client,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPayload {
    /// Standard claims
    pub sub: Option<String>, // Subject
    pub iss: Option<String>,      // Issuer
    pub aud: Option<Vec<String>>, // Audience
    pub exp: Option<i64>,         // Expiration time
    pub nbf: Option<i64>,         // Not before
    pub iat: Option<i64>,         // Issued at
    pub jti: Option<String>,      // JWT ID

    /// Custom claims
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}

/// JWT creation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtResult {
    pub jwt: String,
}

/// JWKS (JSON Web Key Set) structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<JsonWebKey>,
}

/// Individual JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    pub kty: String, // Key type
    #[serde(rename = "use")]
    pub key_use: Option<String>, // Key usage
    pub alg: Option<String>, // Algorithm
    pub kid: Option<String>, // Key ID
    pub n: Option<String>, // Modulus (for RSA)
    pub e: Option<String>, // Exponent (for RSA)
    pub x: Option<String>, // X coordinate (for EC)
    pub y: Option<String>, // Y coordinate (for EC)
    pub crv: Option<String>, // Curve (for EC)
}

impl JsonWebKey {
    /// Convert JWK to DecodingKey for verification
    pub fn to_decoding_key(&self) -> Result<DecodingKey> {
        match self.kty.as_str() {
            "RSA" => {
                if let (Some(n), Some(e)) = (&self.n, &self.e) {
                    DecodingKey::from_rsa_components(n, e)
                        .map_err(|e| SuperTokensError::Generic(format!("Invalid RSA JWK: {}", e)))
                } else {
                    Err(SuperTokensError::Generic(
                        "RSA JWK missing n or e".to_string(),
                    ))
                }
            }
            "EC" => {
                if let (Some(x), Some(y)) = (&self.x, &self.y) {
                    DecodingKey::from_ec_components(x, y)
                        .map_err(|e| SuperTokensError::Generic(format!("Invalid EC JWK: {}", e)))
                } else {
                    Err(SuperTokensError::Generic(
                        "EC JWK missing x or y".to_string(),
                    ))
                }
            }
            _ => Err(SuperTokensError::Generic(format!(
                "Unsupported JWK key type: {}",
                self.kty
            ))),
        }
    }
}

/// OpenID Connect Discovery Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenIdDiscoveryConfiguration {
    pub issuer: String,
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: String,
    #[serde(rename = "authorization_endpoint")]
    pub authorization_endpoint: String,
    #[serde(rename = "token_endpoint")]
    pub token_endpoint: String,
    #[serde(rename = "userinfo_endpoint")]
    pub userinfo_endpoint: String,
    #[serde(rename = "revocation_endpoint")]
    pub revocation_endpoint: String,
    #[serde(rename = "end_session_endpoint")]
    pub end_session_endpoint: String,
    #[serde(rename = "subject_types_supported")]
    pub subject_types_supported: Vec<String>,
    #[serde(rename = "id_token_signing_alg_values_supported")]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(rename = "response_types_supported")]
    pub response_types_supported: Vec<String>,
}

/// Request for creating JWT
#[derive(Serialize)]
struct CreateJwtRequest {
    algorithm: String,
    payload: serde_json::Value,
    #[serde(rename = "jwksDomain")]
    jwks_domain: String,
    validity: Option<i64>,
}

/// Response from creating JWT
#[derive(Deserialize)]
struct CreateJwtResponse {
    status: String,
    jwt: Option<String>,
}

/// Response from getting JWKS
#[derive(Deserialize)]
struct GetJwksResponse {
    status: String,
    keys: Option<Vec<JsonWebKey>>,
}

/// Response from OpenID discovery configuration
#[derive(Deserialize)]
struct OpenIdDiscoveryResponse {
    status: String,
    #[serde(flatten)]
    config: Option<OpenIdDiscoveryConfiguration>,
}

/// Create a JWT with custom payload
pub async fn create_jwt(
    config: &SuperTokensConfig,
    payload: JwtPayload,
    validity_seconds: Option<i64>,
    algorithm: Option<String>,
) -> Result<JwtResult> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/jwt", config.api_domain);

    let request_body = CreateJwtRequest {
        algorithm: algorithm.unwrap_or_else(|| "RS256".to_string()),
        payload: serde_json::to_value(&payload)?,
        jwks_domain: config.api_domain.clone(),
        validity: validity_seconds,
    };

    let mut request = client.post(&url).json(&request_body);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let jwt_response: CreateJwtResponse = response.json().await?;

    match jwt_response.status.as_str() {
        "OK" => {
            let jwt = jwt_response.jwt.ok_or_else(|| {
                SuperTokensError::Generic("JWT creation succeeded but no JWT returned".to_string())
            })?;
            Ok(JwtResult { jwt })
        }
        "UNSUPPORTED_ALGORITHM_ERROR" => Err(SuperTokensError::Generic(
            "Unsupported JWT algorithm".to_string(),
        )),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown JWT creation status: {}",
            jwt_response.status
        ))),
    }
}

/// Get JWKS (JSON Web Key Set) for JWT verification
pub async fn get_jwks(config: &SuperTokensConfig) -> Result<Jwks> {
    let client = create_http_client(config)?;
    let url = format!("{}/recipe/jwt/jwks", config.api_domain);

    let mut request = client.get(&url);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let jwks_response: GetJwksResponse = response.json().await?;

    match jwks_response.status.as_str() {
        "OK" => {
            let keys = jwks_response.keys.unwrap_or_default();
            Ok(Jwks { keys })
        }
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown JWKS status: {}",
            jwks_response.status
        ))),
    }
}

/// Get OpenID Connect discovery configuration
pub async fn get_openid_discovery_configuration(
    config: &SuperTokensConfig,
) -> Result<OpenIdDiscoveryConfiguration> {
    let client = create_http_client(config)?;
    let url = format!("{}/.well-known/openid-configuration", config.api_domain);

    let mut request = client.get(&url);

    if let Some(api_key) = &config.api_key {
        request = request.header("api-key", api_key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let error_text = response.text().await.unwrap_or_default();
        return Err(SuperTokensError::from_response(status, error_text));
    }

    let discovery_response: OpenIdDiscoveryResponse = response.json().await?;

    match discovery_response.status.as_str() {
        "OK" => discovery_response.config.ok_or_else(|| {
            SuperTokensError::Generic(
                "OpenID discovery succeeded but no config returned".to_string(),
            )
        }),
        _ => Err(SuperTokensError::Generic(format!(
            "Unknown OpenID discovery status: {}",
            discovery_response.status
        ))),
    }
}

/// Fetch decoding keys from JWKS
async fn fetch_decoding_keys(config: &SuperTokensConfig) -> Result<HashMap<String, DecodingKey>> {
    let jwks = get_jwks(config).await?;
    let mut keys = HashMap::new();

    for jwk in jwks.keys {
        if let Some(kid) = jwk.kid.clone() {
            match jwk.to_decoding_key() {
                Ok(key) => {
                    keys.insert(kid, key);
                }
                Err(e) => {
                    log::warn!("Failed to convert JWK to decoding key: {}", e);
                }
            }
        }
    }

    Ok(keys)
}

/// Verify a JWT token with proper signature verification
pub async fn verify_jwt(
    config: &SuperTokensConfig,
    jwt: impl Into<String>,
    jwks: Option<Jwks>,
) -> Result<JwtPayload> {
    let jwt_str = jwt.into();

    // Parse header to get kid
    let header = decode_header(&jwt_str)
        .map_err(|e| SuperTokensError::InvalidToken(format!("Invalid JWT header: {}", e)))?;

    let kid = header
        .kid
        .ok_or_else(|| SuperTokensError::InvalidToken("Missing 'kid' in JWT header".to_string()))?;

    // Get decoding keys
    let mut keys = if let Some(provided_jwks) = jwks {
        let mut keys = HashMap::new();
        for jwk in provided_jwks.keys {
            if let Some(jwk_kid) = jwk.kid.clone() {
                if let Ok(key) = jwk.to_decoding_key() {
                    keys.insert(jwk_kid, key);
                }
            }
        }
        keys
    } else {
        fetch_decoding_keys(config).await?
    };

    let decoding_key = keys
        .remove(&kid)
        .ok_or_else(|| SuperTokensError::InvalidToken(format!("Unknown JWK kid: {}", kid)))?;

    // Set up validation
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 60; // 60 seconds leeway for clock skew

    // Decode and verify
    let token_data: TokenData<JwtPayload> =
        decode::<JwtPayload>(&jwt_str, &decoding_key, &validation).map_err(|e| {
            match *e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    SuperTokensError::InvalidToken("Invalid JWT format".to_string())
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    SuperTokensError::InvalidToken("JWT has expired".to_string())
                }
                jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
                    SuperTokensError::InvalidToken("JWT not yet valid (nbf)".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    SuperTokensError::InvalidToken("Invalid JWT signature".to_string())
                }
                _ => SuperTokensError::InvalidToken(format!("JWT verification error: {}", e)),
            }
        })?;

    Ok(token_data.claims)
}

/// Create JWT payload with standard claims
pub fn create_jwt_payload(
    subject: impl Into<String>,
    custom_claims: HashMap<String, serde_json::Value>,
    validity_seconds: Option<i64>,
) -> JwtPayload {
    let now = chrono::Utc::now();
    let iat = now.timestamp();
    let exp = validity_seconds.map(|validity| iat + validity);

    JwtPayload {
        sub: Some(subject.into()),
        iss: None, // Will be set by SuperTokens Core
        aud: None,
        exp,
        nbf: Some(iat),
        iat: Some(iat),
        jti: Some(uuid::Uuid::new_v4().to_string()),
        custom_claims,
    }
}

/// Create JWT for user session
pub async fn create_user_jwt(
    config: &SuperTokensConfig,
    user_id: impl Into<String>,
    user_roles: Option<Vec<String>>,
    user_permissions: Option<Vec<String>>,
    validity_seconds: Option<i64>,
) -> Result<JwtResult> {
    let mut custom_claims = HashMap::new();

    if let Some(roles) = user_roles {
        custom_claims.insert("roles".to_string(), serde_json::to_value(roles)?);
    }

    if let Some(permissions) = user_permissions {
        custom_claims.insert(
            "permissions".to_string(),
            serde_json::to_value(permissions)?,
        );
    }

    let payload = create_jwt_payload(user_id, custom_claims, validity_seconds);

    create_jwt(config, payload, validity_seconds, None).await
}

/// Create JWT for API access
pub async fn create_api_jwt(
    config: &SuperTokensConfig,
    api_key_id: impl Into<String>,
    scopes: Vec<String>,
    validity_seconds: Option<i64>,
) -> Result<JwtResult> {
    let mut custom_claims = HashMap::new();
    custom_claims.insert("scopes".to_string(), serde_json::to_value(scopes)?);
    custom_claims.insert(
        "type".to_string(),
        serde_json::Value::String("api_access".to_string()),
    );

    let payload = create_jwt_payload(api_key_id, custom_claims, validity_seconds);

    create_jwt(config, payload, validity_seconds, None).await
}

/// Extract user information from JWT payload
pub fn extract_user_info_from_jwt(
    payload: &JwtPayload,
) -> Option<(String, Vec<String>, Vec<String>)> {
    let user_id = payload.sub.clone()?;

    let roles = payload
        .custom_claims
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let permissions = payload
        .custom_claims
        .get("permissions")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Some((user_id, roles, permissions))
}

/// Check if JWT has specific scope
pub fn jwt_has_scope(payload: &JwtPayload, scope: &str) -> bool {
    payload
        .custom_claims
        .get("scopes")
        .and_then(|s| s.as_array())
        .map(|scopes| scopes.iter().any(|s| s.as_str() == Some(scope)))
        .unwrap_or(false)
}

/// Get JWT expiration as DateTime
pub fn get_jwt_expiration(payload: &JwtPayload) -> Option<DateTime<Utc>> {
    payload
        .exp
        .map(|exp| DateTime::from_timestamp(exp, 0).unwrap_or_else(|| Utc::now()))
}

/// Check if JWT is expired
pub fn is_jwt_expired(payload: &JwtPayload) -> bool {
    payload
        .exp
        .map(|exp| {
            let now = chrono::Utc::now().timestamp();
            now >= exp
        })
        .unwrap_or(false)
}

/// Get JWT issued at time
pub fn get_jwt_issued_at(payload: &JwtPayload) -> Option<DateTime<Utc>> {
    payload
        .iat
        .map(|iat| DateTime::from_timestamp(iat, 0).unwrap_or_else(|| Utc::now()))
}

/// Get JWT not before time
pub fn get_jwt_not_before(payload: &JwtPayload) -> Option<DateTime<Utc>> {
    payload
        .nbf
        .map(|nbf| DateTime::from_timestamp(nbf, 0).unwrap_or_else(|| Utc::now()))
}

/// Check if JWT is currently valid (considering nbf and exp)
pub fn is_jwt_valid_now(payload: &JwtPayload) -> bool {
    let now = chrono::Utc::now().timestamp();

    // Check not before
    if let Some(nbf) = payload.nbf {
        if now < nbf {
            return false;
        }
    }

    // Check expiration
    if let Some(exp) = payload.exp {
        if now >= exp {
            return false;
        }
    }

    true
}

/// Get remaining JWT validity in seconds
pub fn get_jwt_remaining_validity(payload: &JwtPayload) -> Option<i64> {
    payload.exp.map(|exp| {
        let now = chrono::Utc::now().timestamp();
        (exp - now).max(0)
    })
}

/// Create JWT with custom algorithm
pub async fn create_jwt_with_algorithm(
    config: &SuperTokensConfig,
    payload: JwtPayload,
    algorithm: Algorithm,
    validity_seconds: Option<i64>,
) -> Result<JwtResult> {
    let algorithm_str = match algorithm {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        _ => {
            return Err(SuperTokensError::Generic(
                "Unsupported algorithm".to_string(),
            ));
        }
    };

    create_jwt(
        config,
        payload,
        validity_seconds,
        Some(algorithm_str.to_string()),
    )
    .await
}

/// Validate JWT claims
pub fn validate_jwt_claims(
    payload: &JwtPayload,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
    expected_subject: Option<&str>,
) -> Result<()> {
    // Validate issuer
    if let Some(expected_iss) = expected_issuer {
        match &payload.iss {
            Some(iss) if iss == expected_iss => {}
            Some(iss) => {
                return Err(SuperTokensError::InvalidToken(format!(
                    "Invalid issuer: expected {}, got {}",
                    expected_iss, iss
                )));
            }
            None => {
                return Err(SuperTokensError::InvalidToken(
                    "Missing issuer claim".to_string(),
                ));
            }
        }
    }

    // Validate audience
    if let Some(expected_aud) = expected_audience {
        match &payload.aud {
            Some(aud) if aud.contains(&expected_aud.to_string()) => {}
            Some(_) => {
                return Err(SuperTokensError::InvalidToken(format!(
                    "Invalid audience: expected {}",
                    expected_aud
                )));
            }
            None => {
                return Err(SuperTokensError::InvalidToken(
                    "Missing audience claim".to_string(),
                ));
            }
        }
    }

    // Validate subject
    if let Some(expected_sub) = expected_subject {
        match &payload.sub {
            Some(sub) if sub == expected_sub => {}
            Some(sub) => {
                return Err(SuperTokensError::InvalidToken(format!(
                    "Invalid subject: expected {}, got {}",
                    expected_sub, sub
                )));
            }
            None => {
                return Err(SuperTokensError::InvalidToken(
                    "Missing subject claim".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::create_test_config;

    #[test]
    fn test_jwt_payload_creation() {
        let custom_claims = HashMap::new();
        let payload = create_jwt_payload("user123", custom_claims, Some(3600));

        assert_eq!(payload.sub, Some("user123".to_string()));
        assert!(payload.exp.is_some());
        assert!(payload.iat.is_some());
        assert!(payload.jti.is_some());
    }

    #[test]
    fn test_jwt_expiration() {
        let mut payload = JwtPayload {
            exp: Some(chrono::Utc::now().timestamp() - 100), // Expired 100 seconds ago
            ..Default::default()
        };
        assert!(is_jwt_expired(&payload));

        payload.exp = Some(chrono::Utc::now().timestamp() + 100); // Expires in 100 seconds
        assert!(!is_jwt_expired(&payload));
    }

    #[test]
    fn test_jwt_scope_check() {
        let mut payload = JwtPayload {
            custom_claims: HashMap::new(),
            ..Default::default()
        };

        payload.custom_claims.insert(
            "scopes".to_string(),
            serde_json::json!(["read", "write", "admin"]),
        );

        assert!(jwt_has_scope(&payload, "read"));
        assert!(jwt_has_scope(&payload, "admin"));
        assert!(!jwt_has_scope(&payload, "delete"));
    }

    #[tokio::test]
    #[ignore] // Requires running SuperTokens Core
    async fn test_jwt_flow() {
        use crate::jwt::{create_jwt, create_jwt_payload, get_jwks, verify_jwt};
        use std::collections::HashMap;
        let config = create_test_config();

        // 1. Fetch JWKS
        let jwks = get_jwks(&config).await;
        assert!(jwks.is_ok(), "Failed to fetch JWKS: {:?}", jwks.err());
        let jwks = jwks.unwrap();
        assert!(!jwks.keys.is_empty(), "JWKS keys should not be empty");

        // 2. Create a JWT for a test user
        let payload = create_jwt_payload("test_user", HashMap::new(), Some(3600));
        let jwt_result = create_jwt(&config, payload.clone(), Some(3600), None).await;
        assert!(
            jwt_result.is_ok(),
            "JWT creation failed: {:?}",
            jwt_result.err()
        );
        let jwt_str = jwt_result.unwrap().jwt;
        assert!(!jwt_str.is_empty(), "Created JWT should not be empty");

        // 3. Verify the JWT
        let verified_payload = verify_jwt(&config, &jwt_str, Some(jwks)).await;
        assert!(
            verified_payload.is_ok(),
            "JWT verification failed: {:?}",
            verified_payload.err()
        );
        let verified_payload = verified_payload.unwrap();

        // 4. Assert claims match
        assert_eq!(verified_payload.sub.as_deref(), Some("test_user"));
        assert_eq!(verified_payload.custom_claims.len(), 0);
        assert!(verified_payload.exp.is_some(), "Expiration claim missing");
        assert!(verified_payload.iat.is_some(), "Issued-at claim missing");
    }
}

impl Default for JwtPayload {
    fn default() -> Self {
        Self {
            sub: None,
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            custom_claims: HashMap::new(),
        }
    }
}
