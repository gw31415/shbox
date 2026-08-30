//! Structured logging: `tracing` compact text on stderr with UTC RFC 3339
//! timestamps and a runtime-replaceable level filter (driven by reload in a
//! later milestone).

use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogLevel;

/// Install the global subscriber. Panics only if called twice in one process.
pub fn init(level: LevelFilter) -> Logging {
    let (filter, handle) = reload::Layer::new(level);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_timer(UtcTime::rfc_3339())
                .with_writer(std::io::stderr),
        )
        .with(filter)
        .init();
    Logging {
        set_level: std::sync::Arc::new(move |level| {
            let _ = handle.modify(|current| *current = level);
        }),
    }
}

/// The tracing filter matching a configured `log_level`.
pub fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    }
}

/// Initialized logging with a dynamic level handle.
#[derive(Clone)]
pub struct Logging {
    set_level: std::sync::Arc<dyn Fn(LevelFilter) + Send + Sync>,
}

impl Logging {
    /// Replace the active level filter without touching existing output.
    pub fn set_level(&self, level: LevelFilter) {
        (self.set_level)(level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogLevel;

    #[test]
    fn maps_every_config_level_to_a_filter() {
        assert_eq!(level_filter(LogLevel::Error), LevelFilter::ERROR);
        assert_eq!(level_filter(LogLevel::Warn), LevelFilter::WARN);
        assert_eq!(level_filter(LogLevel::Info), LevelFilter::INFO);
        assert_eq!(level_filter(LogLevel::Debug), LevelFilter::DEBUG);
        assert_eq!(level_filter(LogLevel::Trace), LevelFilter::TRACE);
    }
}
