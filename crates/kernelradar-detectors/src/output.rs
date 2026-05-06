/// Global output format selection (T-1.4).
///
/// Set once at process startup by the CLI based on `--format` flag
/// and runtime detection of systemd journal stream.
///
/// • Plain    — colored human text on stdout (interactive use)
/// • Json     — one JSON object per line on stdout (file logging, jq, SIEM)
/// • Journald — tracing events with structured fields; tracing-journald
///              layer ships them to systemd's journal as custom fields
///              like DETECTOR=, SEVERITY=, PID=...

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat { Plain, Json, Journald }

static OUTPUT_FORMAT: OnceLock<OutputFormat> = OnceLock::new();

/// Initialise once. Subsequent calls are no-ops.
pub fn set_output_format(f: OutputFormat) {
    let _ = OUTPUT_FORMAT.set(f);
}

pub fn global_output_format() -> OutputFormat {
    *OUTPUT_FORMAT.get().unwrap_or(&OutputFormat::Plain)
}

/// Auto-detect when running under systemd.
/// systemd sets `JOURNAL_STREAM` (and `INVOCATION_ID`).
pub fn detect_systemd_environment() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some()
        || std::env::var_os("INVOCATION_ID").is_some()
}
