use rand::RngCore;
use std::time::Duration;
use tokio::time::sleep;

use crate::session::{RefreshResult, refresh_session};

/// Session refresh configuration
#[derive(Debug, Clone)]
pub struct RefreshConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial delay between retries in milliseconds
    pub initial_delay_ms: u64,
    /// Maximum delay between retries in milliseconds
    pub max_delay_ms: u64,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 5000,
        }
    }
}

/// Helper function to refresh a session with exponential backoff
pub async fn refresh_session_with_retry(
    config: &crate::config::SuperTokensConfig,
    refresh_token: &str,
    refresh_config: Option<RefreshConfig>,
) -> crate::Result<RefreshResult> {
    let refresh_config = refresh_config.unwrap_or_default();
    let mut last_error = None;
    let mut rng = rand::thread_rng();

    for attempt in 0..refresh_config.max_retries {
        match refresh_session(config, refresh_token).await {
            Ok(session) => return Ok(session),
            Err(e) => {
                if !matches!(e, crate::errors::SuperTokensError::NetworkError(_)) {
                    return Err(e);
                }
                last_error = Some(e);

                if attempt < refresh_config.max_retries - 1 {
                    // Calculate exponential backoff with jitter
                    let base_delay = refresh_config
                        .initial_delay_ms
                        .saturating_mul(2_u64.pow(attempt));
                    let max_delay = refresh_config.max_delay_ms;
                    let actual_delay = base_delay.min(max_delay);

                    // Add jitter (±10%)
                    let jitter = (rng.next_u64() as f64 * 0.2 - 0.1) * actual_delay as f64;
                    let delay = Duration::from_millis((actual_delay as f64 + jitter) as u64);

                    sleep(delay).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        crate::errors::SuperTokensError::Generic("Failed to refresh session".to_string())
    }))
}
