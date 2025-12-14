//! Logging configuration

use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

/// Initialize logging with the specified level
pub fn init(level: &str, json: bool) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let subscriber = tracing_subscriber::registry().with(filter);

    if json {
        subscriber
            .with(fmt::layer().json())
            .try_init()
            .map_err(|e| anyhow::anyhow!("Failed to init logging: {}", e))?;
    } else {
        subscriber
            .with(fmt::layer().with_target(true).with_thread_ids(false))
            .try_init()
            .map_err(|e| anyhow::anyhow!("Failed to init logging: {}", e))?;
    }

    Ok(())
}
