//! Configuration management for SuperTokens SDK

use crate::errors::{Result, SuperTokensError};
use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

/// SuperTokens SDK configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperTokensConfig {
    /// SuperTokens Core API domain (e.g., "http://localhost:3567")
    pub api_domain: String,

    /// Application name
    pub app_name: String,

    /// Website domain where your frontend is hosted
    pub website_domain: String,

    /// Optional API key for authentication with SuperTokens Core
    pub api_key: Option<String>,

    /// Additional configuration options
    pub options: SuperTokensOptions,
}

/// Additional configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperTokensOptions {
    /// HTTP request timeout in seconds (default: 30)
    pub timeout_seconds: u64,

    /// Maximum number of retries for failed requests (default: 3)
    pub max_retries: u32,

    /// Base delay in milliseconds for retry backoff (default: 1000)
    pub retry_delay_ms: u64,

    /// Enable debug logging (default: false)
    pub debug_logging: bool,
}

impl Default for SuperTokensOptions {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_retries: 3,
            retry_delay_ms: 1000,
            debug_logging: false,
        }
    }
}

impl SuperTokensConfig {
    /// Create a new SuperTokens configuration
    ///
    /// # Arguments
    ///
    /// * `api_domain` - SuperTokens Core API domain
    /// * `app_name` - Your application name
    /// * `website_domain` - Your frontend domain
    ///
    /// # Example
    ///
    /// ```rust
    /// use supertokens_sdk::SuperTokensConfig;
    ///
    /// let config = SuperTokensConfig::new(
    ///     "http://localhost:3567",
    ///     "MyApp",
    ///     "http://localhost:3000"
    /// );
    /// ```
    pub fn new(
        api_domain: impl Into<String>,
        app_name: impl Into<String>,
        website_domain: impl Into<String>,
    ) -> Self {
        Self {
            api_domain: api_domain.into(),
            app_name: app_name.into(),
            website_domain: website_domain.into(),
            api_key: None,
            options: SuperTokensOptions::default(),
        }
    }

    /// Set the API key for authentication with SuperTokens Core
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Set request timeout in seconds
    pub fn with_timeout(mut self, timeout_seconds: u64) -> Self {
        self.options.timeout_seconds = timeout_seconds;
        self
    }

    /// Set maximum number of retries for failed requests
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.options.max_retries = max_retries;
        self
    }

    /// Set retry delay in milliseconds
    pub fn with_retry_delay(mut self, retry_delay_ms: u64) -> Self {
        self.options.retry_delay_ms = retry_delay_ms;
        self
    }

    /// Enable debug logging
    pub fn with_debug_logging(mut self, debug: bool) -> Self {
        self.options.debug_logging = debug;
        self
    }

    /// Set custom options
    pub fn with_options(mut self, options: SuperTokensOptions) -> Self {
        self.options = options;
        self
    }

    /// Load configuration from environment variables
    ///
    /// Required environment variables:
    /// - `SUPERTOKENS_API_DOMAIN`: SuperTokens Core API domain
    /// - `SUPERTOKENS_APP_NAME`: Application name
    /// - `SUPERTOKENS_WEBSITE_DOMAIN`: Website domain
    ///
    /// Optional environment variables:
    /// - `SUPERTOKENS_API_KEY`: API key for SuperTokens Core
    /// - `SUPERTOKENS_TIMEOUT_SECONDS`: Request timeout (default: 30)
    /// - `SUPERTOKENS_MAX_RETRIES`: Maximum retries (default: 3)
    /// - `SUPERTOKENS_RETRY_DELAY_MS`: Retry delay in ms (default: 1000)
    /// - `SUPERTOKENS_DEBUG_LOGGING`: Enable debug logging (default: false)
    ///
    /// # Example
    ///
    /// ```bash
    /// export SUPERTOKENS_API_DOMAIN=http://localhost:3567
    /// export SUPERTOKENS_APP_NAME=MyApp
    /// export SUPERTOKENS_WEBSITE_DOMAIN=http://localhost:3000
    /// export SUPERTOKENS_API_KEY=your_api_key
    /// ```
    ///
    /// ```rust
    /// use supertokens_sdk::SuperTokensConfig;
    ///
    /// let config = SuperTokensConfig::from_env()?;
    /// ```
    pub fn from_env() -> Result<Self> {
        // Load .env file if present
        dotenvy::dotenv().ok();

        let api_domain = env::var("SUPERTOKENS_API_DOMAIN").map_err(|_| {
            SuperTokensError::Generic(
                "SUPERTOKENS_API_DOMAIN environment variable is required".to_string(),
            )
        })?;

        let app_name = env::var("SUPERTOKENS_APP_NAME").map_err(|_| {
            SuperTokensError::Generic(
                "SUPERTOKENS_APP_NAME environment variable is required".to_string(),
            )
        })?;

        let website_domain = env::var("SUPERTOKENS_WEBSITE_DOMAIN").map_err(|_| {
            SuperTokensError::Generic(
                "SUPERTOKENS_WEBSITE_DOMAIN environment variable is required".to_string(),
            )
        })?;

        let api_key = env::var("SUPERTOKENS_API_KEY").ok();

        let timeout_seconds = env::var("SUPERTOKENS_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .unwrap_or(30);

        let max_retries = env::var("SUPERTOKENS_MAX_RETRIES")
            .unwrap_or_else(|_| "3".to_string())
            .parse()
            .unwrap_or(3);

        let retry_delay_ms = env::var("SUPERTOKENS_RETRY_DELAY_MS")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .unwrap_or(1000);

        let debug_logging = env::var("SUPERTOKENS_DEBUG_LOGGING")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let options = SuperTokensOptions {
            timeout_seconds,
            max_retries,
            retry_delay_ms,
            debug_logging,
        };

        Ok(Self {
            api_domain,
            app_name,
            website_domain,
            api_key,
            options,
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate API domain
        if self.api_domain.is_empty() {
            return Err(SuperTokensError::Generic(
                "API domain cannot be empty".to_string(),
            ));
        }

        if let Err(_) = Url::parse(&self.api_domain) {
            return Err(SuperTokensError::Generic(format!(
                "Invalid API domain URL: {}",
                self.api_domain
            )));
        }

        // Validate app name
        if self.app_name.is_empty() {
            return Err(SuperTokensError::Generic(
                "App name cannot be empty. Give it a name".to_string(),
            ));
        }

        if self.app_name.len() > 100 {
            return Err(SuperTokensError::Generic(
                "App name too long (max 100 characters)".to_string(),
            ));
        }

        // Validate website domain
        if self.website_domain.is_empty() {
            return Err(SuperTokensError::Generic(
                "Website domain cannot be empty".to_string(),
            ));
        }

        if let Err(_) = Url::parse(&self.website_domain) {
            return Err(SuperTokensError::Generic(format!(
                "Invalid website domain URL: {}",
                self.website_domain
            )));
        }

        // Validate options
        if self.options.timeout_seconds == 0 {
            return Err(SuperTokensError::Generic(
                "Timeout must be greater than 0".to_string(),
            ));
        }

        if self.options.timeout_seconds > 300 {
            return Err(SuperTokensError::Generic(
                "Timeout too long (max 300 seconds)".to_string(),
            ));
        }

        if self.options.max_retries > 10 {
            return Err(SuperTokensError::Generic(
                "Too many retries (max 10)".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the full API URL for an endpoint
    pub fn get_api_url(&self, endpoint: &str) -> String {
        let base = self.api_domain.trim_end_matches('/');
        let endpoint = endpoint.trim_start_matches('/');
        format!("{}/{}", base, endpoint)
    }

    /// Check if API key is configured
    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// Check if debug logging is enabled
    pub fn is_debug_enabled(&self) -> bool {
        self.options.debug_logging
    }
}

/// Builder for SuperTokens configuration
pub struct SuperTokensConfigBuilder {
    config: SuperTokensConfig,
}

impl SuperTokensConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self {
            config: SuperTokensConfig {
                api_domain: String::new(),
                app_name: String::new(),
                website_domain: String::new(),
                api_key: None,
                options: SuperTokensOptions::default(),
            },
        }
    }

    /// Set API domain
    pub fn api_domain(mut self, domain: impl Into<String>) -> Self {
        self.config.api_domain = domain.into();
        self
    }

    /// Set app name
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.config.app_name = name.into();
        self
    }

    /// Set website domain
    pub fn website_domain(mut self, domain: impl Into<String>) -> Self {
        self.config.website_domain = domain.into();
        self
    }

    /// Set API key
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.config.api_key = Some(key.into());
        self
    }

    /// Set options
    pub fn options(mut self, options: SuperTokensOptions) -> Self {
        self.config.options = options;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<SuperTokensConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for SuperTokensConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config =
            SuperTokensConfig::new("http://localhost:3567", "TestApp", "http://localhost:3000");

        assert_eq!(config.api_domain, "http://localhost:3567");
        assert_eq!(config.app_name, "TestApp");
        assert_eq!(config.website_domain, "http://localhost:3000");
        // assert!(config.api_key.is_none());
    }

    #[test]
    fn test_config_with_api_key() {
        let config =
            SuperTokensConfig::new("http://localhost:3567", "TestApp", "http://localhost:3000")
                .with_api_key("test_key");

        assert_eq!(config.api_key, Some("test_key".to_string()));
        assert!(config.has_api_key());
    }

    #[test]
    fn test_config_validation() {
        let config =
            SuperTokensConfig::new("http://localhost:3567", "TestApp", "http://localhost:3000");

        assert!(config.validate().is_ok());

        // Test invalid URL
        let invalid_config =
            SuperTokensConfig::new("invalid-url", "TestApp", "http://localhost:3000");
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_get_api_url() {
        let config =
            SuperTokensConfig::new("http://localhost:3567", "TestApp", "http://localhost:3000");

        assert_eq!(
            config.get_api_url("/recipe/session/verify"),
            "http://localhost:3567/recipe/session/verify"
        );
        assert_eq!(
            config.get_api_url("recipe/session/verify"),
            "http://localhost:3567/recipe/session/verify"
        );
    }

    #[test]
    fn test_builder_pattern() {
        let config = SuperTokensConfigBuilder::new()
            .api_domain("http://localhost:3567")
            .app_name("TestApp")
            .website_domain("http://localhost:3000")
            .api_key("test_key")
            .build()
            .unwrap();

        assert_eq!(config.api_domain, "http://localhost:3567");
        assert_eq!(config.app_name, "TestApp");
        assert_eq!(config.website_domain, "http://localhost:3000");
        assert_eq!(config.api_key, Some("test_key".to_string()));
    }
}
