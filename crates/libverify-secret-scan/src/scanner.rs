use regex::Regex;

use crate::entropy::shannon_entropy;
use crate::rules::{builtin_rules, SecretRule};

// ---------------------------------------------------------------------------
// Stopword filter (betterleaks generic-api-key style)
// ---------------------------------------------------------------------------

/// Common words / patterns that look like secrets but aren't.
/// Drawn from betterleaks' stopword list, trimmed to common false positives.
const STOPWORDS: &[&str] = &[
    "example", "sample", "placeholder", "changeme", "password", "undefined",
    "xxxxxxxx", "yyyyyyyy", "zzzzzzzz", "00000000", "11111111", "12345678",
    "abcdefgh", "testtest", "redacted", "censored", "aaaaaaaa", "bbbbbbbb",
    "deadbeef", "replace_me", "your_key_here", "your_token", "insert_here",
    "your_api_key", "your_secret", "enter_your", "fixme", "todo",
    "template", "function", "prototype", "constructor", "interface",
    "abstract", "document", "application", "urlencoded", "multipart",
    "boundary", "localhost", "127.0.0.1", "0.0.0.0",
    "true", "false", "null", "none",
];

fn is_stopword(secret: &str) -> bool {
    let lower = secret.to_ascii_lowercase();
    STOPWORDS.iter().any(|sw| lower.contains(sw))
}

// ---------------------------------------------------------------------------
// Global allowlist patterns
// ---------------------------------------------------------------------------

fn global_allowlist_patterns() -> Vec<Regex> {
    let patterns = [
        // Repeated characters
        r"^(.)\1{7,}$",
        // Shell/template variables
        r"^\$\{.+\}$",
        r"^\{\{.+\}\}$",
        r"^%\(.+\)s$",
        // Obvious placeholders
        r"(?i)^<[a-z_\-\s]+>$",
        r"(?i)\b(?:example|test|fake|dummy|mock|sample)\b",
        // URL without credentials
        r"^https?://[a-z0-9\-]+\.[a-z]{2,}",
    ];
    patterns
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A single secret finding from the scanner.
#[derive(Debug, Clone)]
pub struct SecretFinding {
    /// File name where the secret was found.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// Rule ID that matched.
    pub rule_id: String,
}

/// Platform-agnostic secret scanner.
///
/// Create once (rules are compiled at construction) and call [`Scanner::scan`]
/// for each source file.
pub struct Scanner {
    rules: Vec<SecretRule>,
    global_allowlist: Vec<Regex>,
    /// Additional platform-specific allowlist patterns.
    extra_allowlist: Vec<Regex>,
}

impl Scanner {
    /// Create a scanner with built-in rules.
    pub fn new() -> Self {
        Self {
            rules: builtin_rules(),
            global_allowlist: global_allowlist_patterns(),
            extra_allowlist: Vec::new(),
        }
    }

    /// Add extra allowlist regex patterns (platform-specific FP suppression).
    pub fn add_allowlist_patterns(&mut self, patterns: &[&str]) {
        for pat in patterns {
            if let Ok(re) = Regex::new(pat) {
                self.extra_allowlist.push(re);
            }
        }
    }

    /// Return the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a single source string and return findings.
    pub fn scan(&self, file_name: &str, source: &str) -> Vec<SecretFinding> {
        let source_lower = source.to_ascii_lowercase();
        let mut hits = Vec::new();

        for rule in &self.rules {
            // Keyword pre-filter: skip rule if none of its keywords appear.
            if !rule.keywords.is_empty()
                && !rule.keywords.iter().any(|kw| source_lower.contains(kw))
            {
                continue;
            }

            for (line_idx, line) in source.lines().enumerate() {
                for cap in rule.regex.captures_iter(line) {
                    let secret = cap
                        .get(rule.secret_group)
                        .or_else(|| cap.get(0))
                        .map(|m| m.as_str())
                        .unwrap_or("");

                    if secret.is_empty() {
                        continue;
                    }

                    // Entropy gate.
                    if rule.entropy > 0.0 && shannon_entropy(secret) < rule.entropy {
                        continue;
                    }

                    // Stopword + global allowlist (only for generic/catch-all rules).
                    if rule.generic {
                        if is_stopword(secret) {
                            continue;
                        }
                        if self
                            .global_allowlist
                            .iter()
                            .any(|re| re.is_match(secret))
                        {
                            continue;
                        }
                    }

                    // Rule-specific allowlist.
                    if rule.allowlist.iter().any(|re| re.is_match(secret) || re.is_match(line)) {
                        continue;
                    }

                    // Extra platform-specific allowlist.
                    if self.extra_allowlist.iter().any(|re| re.is_match(secret) || re.is_match(line)) {
                        continue;
                    }

                    hits.push(SecretFinding {
                        file: file_name.to_string(),
                        line: line_idx + 1,
                        rule_id: rule.id.to_string(),
                    });

                    // One hit per rule per line is enough.
                    break;
                }
            }
        }

        hits
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_line(source: &str) -> Vec<SecretFinding> {
        Scanner::new().scan("test", source)
    }

    fn assert_detected(source: &str, expected_rule: &str) {
        let findings = scan_line(source);
        assert!(
            findings.iter().any(|f| f.rule_id == expected_rule),
            "expected rule '{}' to match in: {}\nfindings: {:?}",
            expected_rule, source, findings
        );
    }

    fn assert_clean(source: &str) {
        let findings = scan_line(source);
        assert!(
            findings.is_empty(),
            "expected no findings for: {}\nfindings: {:?}",
            source, findings
        );
    }

    // ── True positives ─────────────────────────────────────────────────

    #[test]
    fn google_api_key() {
        assert_detected(
            "var k = 'AIzaSyA1234567890abcdefghijklmnopqrstuvw';",
            "google-api-key",
        );
    }

    #[test]
    fn google_oauth_access_token() {
        assert_detected(
            "var tok = 'ya29.a0ARrdaM_FAKE1234567890abcdefXY';",
            "google-oauth-access-token",
        );
    }

    #[test]
    fn aws_access_key_id() {
        assert_detected("var key = 'AKIAIOSFODNN7EXAMPLE';", "aws-access-key-id");
    }

    #[test]
    fn github_pat() {
        assert_detected(
            "var t = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';",
            "github-pat",
        );
    }

    #[test]
    fn github_fine_grained_pat() {
        assert_detected(
            "var t = 'github_pat_11AABCC22_xyzxyzxyzxyzxyzxyzxyzxyz';",
            "github-fine-grained-pat",
        );
    }

    #[test]
    fn slack_bot_token() {
        // Build test token at runtime to avoid push protection
        let token = format!("var t = 'xoxb-{}-{}';", "1234567890", "abcdefghijklmnopqrst");
        assert_detected(&token, "slack-bot-token");
    }

    #[test]
    fn slack_webhook() {
        // Build test URL at runtime to avoid push protection
        let url = format!(
            "var u = 'https://hooks.slack.com/services/{}/{}/{}';",
            "T12345678", "B12345678", "abcdefghijklmnopqrstuvwx"
        );
        assert_detected(&url, "slack-webhook");
    }

    #[test]
    fn stripe_secret_key() {
        // Build test key at runtime to avoid push protection
        let key = format!("var k = '{}{}';", "sk_live_", "abcdefghijklmnopqrstuvwx");
        assert_detected(&key, "stripe-secret-key");
    }

    #[test]
    fn sendgrid_api_key() {
        assert_detected(
            "var sg = 'SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRSTU';",
            "sendgrid-api-key",
        );
    }

    #[test]
    fn openai_project_key() {
        assert_detected(
            "var k = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD';",
            "openai-project-key",
        );
    }

    #[test]
    fn anthropic_api_key() {
        let sk = format!("var k = 'sk-ant-{}';", "a".repeat(80));
        assert_detected(&sk, "anthropic-api-key");
    }

    #[test]
    fn private_key_pem() {
        assert_detected(
            "var pk = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEow';",
            "private-key-pem",
        );
    }

    #[test]
    fn huggingface_token() {
        assert_detected(
            "var hf = 'hf_abcdefghijklmnopqrstuvwxyz12345';",
            "huggingface-token",
        );
    }

    #[test]
    fn generic_api_key_high_entropy() {
        assert_detected(
            r#"var secret = "a9ZkL3xQ7mR5wB2iP4nT";"#,
            "generic-api-key",
        );
    }

    // ── False positive suppression ─────────────────────────────────────

    #[test]
    fn fp_placeholder() {
        assert_clean(r#"var token = "your_api_key_here";"#);
    }

    #[test]
    fn fp_low_entropy_generic() {
        assert_clean(r#"var secret = "abcdefghijkl";"#);
    }

    #[test]
    fn fp_template_variable() {
        assert_clean(r#"var token = "${API_TOKEN}";"#);
    }

    #[test]
    fn fp_all_alpha_generic() {
        assert_clean(r#"var secret = "abcdefghijklmn";"#);
    }

    #[test]
    fn fp_localhost_connection_string() {
        assert_clean(r#"var db = "postgres://user:pass@localhost:5432/mydb";"#);
    }

    // ── Extra allowlist ────────────────────────────────────────────────

    #[test]
    fn extra_allowlist_suppresses() {
        let mut scanner = Scanner::new();
        scanner.add_allowlist_patterns(&[r"(?i)PropertiesService\."]);
        let findings = scanner.scan(
            "test",
            r#"var key = PropertiesService.getScriptProperties().getProperty("API_KEY");"#,
        );
        assert!(findings.is_empty());
    }

    // ── Multi-file ─────────────────────────────────────────────────────

    #[test]
    fn reports_correct_line_numbers() {
        let source = "line1\nvar k = 'AIzaSyA1234567890abcdefghijklmnopqrstuvw';\nline3";
        let findings = scan_line(source);
        assert_eq!(findings[0].line, 2);
    }
}
