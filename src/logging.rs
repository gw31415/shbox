//! Structured logging: `tracing` compact text on stderr with UTC RFC 3339
//! timestamps. The level is fixed once at startup, from the config file's
//! `log_level` with the `--log-level` flag layered on top; SIGHUP cannot
//! change it.

use std::sync::atomic::{AtomicBool, Ordering};

use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::prelude::*;

use crate::config::LogLevel;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Install the global subscriber at the startup-selected level. Panics only
/// if called twice in one process.
pub fn init(level: LevelFilter) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_timer(UtcTime::rfc_3339())
                .with_writer(std::io::stderr),
        )
        .with(level)
        .init();
    INITIALIZED.store(true, Ordering::Release);
}

/// Whether `init` has installed the global subscriber. Startup can fail
/// before `init` runs — the config file is one of its own inputs — and such
/// failures must fall back to plain stderr reporting.
pub fn initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// The tracing filter matching the startup-selected log level.
pub fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
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
