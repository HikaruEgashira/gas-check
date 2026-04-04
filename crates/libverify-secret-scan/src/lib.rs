//! Platform-agnostic secret scanning engine for the libverify ecosystem.
//!
//! Algorithm inspired by [betterleaks](https://github.com/betterleaks/betterleaks):
//! - Keyword pre-filtering per rule for fast skip
//! - Shannon entropy gating on extracted secret values
//! - Stopword / allowlist filtering to suppress false positives
//! - Capture-group extraction to isolate the secret from context

mod entropy;
mod rules;
mod scanner;

pub use entropy::shannon_entropy;
pub use rules::{builtin_rules, SecretRule};
pub use scanner::{Scanner, SecretFinding};
