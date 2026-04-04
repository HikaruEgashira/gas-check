use regex::Regex;

/// A single secret detection rule.
///
/// Modelled after betterleaks' `Rule` struct: each rule has an identifier,
/// a regex, optional keyword pre-filter, entropy threshold, capture group
/// selection, and allowlists for false-positive suppression.
pub struct SecretRule {
    /// Unique rule identifier (e.g., `"google-api-key"`).
    pub id: &'static str,
    /// Detection regex. May contain capture groups.
    pub regex: Regex,
    /// Which capture group holds the secret value (0 = whole match).
    pub secret_group: usize,
    /// Minimum Shannon entropy for the extracted secret. 0 = no entropy check.
    pub entropy: f64,
    /// Lowercase keywords that must appear in the source for this rule to fire.
    /// Empty means always checked (expensive — use sparingly).
    pub keywords: &'static [&'static str],
    /// Rule-specific allowlist regexes (applied to extracted secret AND line).
    pub allowlist: Vec<Regex>,
    /// Whether to apply stopword + global allowlist filtering.
    /// Only true for generic catch-all rules where FP risk is high.
    pub generic: bool,
}

/// Build the full catalogue of built-in secret detection rules.
///
/// Rules are ported from / inspired by [betterleaks.toml](https://github.com/betterleaks/betterleaks).
pub fn builtin_rules() -> Vec<SecretRule> {
    let mut rules = Vec::new();

    macro_rules! rule {
        ($id:expr, $re:expr, $sg:expr, $ent:expr, $kw:expr) => {
            if let Ok(regex) = Regex::new($re) {
                rules.push(SecretRule {
                    id: $id,
                    regex,
                    secret_group: $sg,
                    entropy: $ent,
                    keywords: $kw,
                    allowlist: Vec::new(),
                    generic: false,
                });
            }
        };
        ($id:expr, $re:expr, $sg:expr, $ent:expr, $kw:expr, allow: [$($aw:expr),*]) => {
            if let Ok(regex) = Regex::new($re) {
                let mut allowlist: Vec<Regex> = Vec::new();
                $( if let Ok(r) = Regex::new($aw) { allowlist.push(r); } )*
                rules.push(SecretRule {
                    id: $id,
                    regex,
                    secret_group: $sg,
                    entropy: $ent,
                    keywords: $kw,
                    allowlist,
                    generic: false,
                });
            }
        };
    }

    // ── Google ─────────────────────────────────────────────���────────────
    rule!("google-api-key",
        r"AIza[0-9A-Za-z\-_]{35}",
        0, 3.0, &["aiza"]);

    rule!("google-oauth-client-secret",
        r#"(?i)(?:client[_\-]?secret)\s*[:=]\s*["']([0-9A-Za-z\-_]{24,})["']"#,
        1, 3.0, &["client_secret", "clientsecret", "client-secret"]);

    rule!("google-service-account-key",
        r#""private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY"#,
        0, 0.0, &["private_key", "begin"]);

    rule!("google-oauth-access-token",
        r"ya29\.[0-9A-Za-z\-_]{30,}",
        0, 3.0, &["ya29"]);

    // ── AWS ────────────────────────────────────────────────────────────
    rule!("aws-access-key-id",
        r"(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)",
        1, 0.0, &["akia"]);

    rule!("aws-secret-access-key",
        r#"(?i)(?:aws_?secret_?access_?key|secret_?access_?key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
        1, 4.0, &["secret_access_key", "aws_secret"]);

    // ── GitHub ─────────────────────────────────────────────────────────
    rule!("github-pat",
        r"ghp_[A-Za-z0-9_]{36,}",
        0, 0.0, &["ghp_"]);

    rule!("github-oauth-token",
        r"gho_[A-Za-z0-9_]{36,}",
        0, 0.0, &["gho_"]);

    rule!("github-app-token",
        r"(?:ghu|ghs)_[A-Za-z0-9_]{36,}",
        0, 0.0, &["ghu_", "ghs_"]);

    rule!("github-fine-grained-pat",
        r"github_pat_[A-Za-z0-9_]{22,}",
        0, 0.0, &["github_pat_"]);

    // ── GitLab ─────────────────────────────────────────────────────────
    rule!("gitlab-pat",
        r"glpat-[A-Za-z0-9\-_]{20,}",
        0, 0.0, &["glpat-"]);

    // ── Slack ──────────────────────────────────────────────────────────
    rule!("slack-bot-token",
        r"xoxb-[0-9]{10,}-[0-9A-Za-z\-]{20,}",
        0, 0.0, &["xoxb"]);

    rule!("slack-user-token",
        r"xoxp-[0-9]{10,}-[0-9A-Za-z\-]{20,}",
        0, 0.0, &["xoxp"]);

    rule!("slack-webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
        0, 0.0, &["hooks.slack.com"]);

    // ── Stripe ─────────────────────────────────────────────────────────
    rule!("stripe-secret-key",
        r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}",
        0, 0.0, &["sk_live", "sk_test", "rk_live", "rk_test"]);

    rule!("stripe-publishable-key",
        r"pk_(?:live|test)_[A-Za-z0-9]{20,}",
        0, 0.0, &["pk_live", "pk_test"]);

    // ── Twilio ─────────────────────────────────────────────────────────
    rule!("twilio-api-key",
        r"SK[0-9a-fA-F]{32}",
        0, 3.0, &["twilio", "sk"]);

    // ── SendGrid ───────────────────────────────────────────────────────
    rule!("sendgrid-api-key",
        r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}",
        0, 0.0, &["sg."]);

    // ── Mailchimp ──────────────────────────────────────────────────────
    rule!("mailchimp-api-key",
        r"[0-9a-f]{32}-us[0-9]{1,2}",
        0, 3.0, &["mailchimp"]);

    // ── OpenAI ─────────────────────────────────────────────────────────
    rule!("openai-api-key",
        r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
        0, 0.0, &["sk-"]);

    rule!("openai-project-key",
        r"sk-proj-[A-Za-z0-9\-_]{40,}",
        0, 0.0, &["sk-proj-"]);

    // ── Anthropic ──────────────────────────────────────────────────────
    rule!("anthropic-api-key",
        r"sk-ant-[A-Za-z0-9\-_]{80,}",
        0, 0.0, &["sk-ant-"]);

    // ── Azure ──────────────────────────────────────────────────────────
    rule!("azure-storage-account-key",
        r#"(?i)(?:account_?key|storage_?key)\s*[:=]\s*["']?([A-Za-z0-9+/]{86}==)["']?"#,
        1, 4.5, &["account_key", "accountkey", "storage_key"]);

    // ── Firebase ───────────────────────────────────────────────────────
    rule!("firebase-cloud-messaging",
        r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}",
        0, 0.0, &["aaaa"]);

    // ── Heroku ─────────────────────────────────────────────────────────
    rule!("heroku-api-key",
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        0, 3.0, &["heroku"],
        allow: [r"(?i)(?:script[_\-]?id|file[_\-]?id|sheet[_\-]?id|drive|doc)"]);

    // ── Shopify ────────────────────────────────────────────────────────
    rule!("shopify-access-token",
        r"shpat_[a-fA-F0-9]{32}",
        0, 0.0, &["shpat_"]);

    rule!("shopify-shared-secret",
        r"shpss_[a-fA-F0-9]{32}",
        0, 0.0, &["shpss_"]);

    // ── Telegram ───────────────────────────────────────────────────────
    rule!("telegram-bot-token",
        r"[0-9]{5,}:AA[A-Za-z0-9\-_]{33,}",
        0, 3.0, &["telegram", "bot"]);

    // ── Discord ────────────────────────────────────────────────────────
    rule!("discord-bot-token",
        r"[MN][A-Za-z0-9\-_]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}",
        0, 3.5, &["discord"]);

    rule!("discord-webhook",
        r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9\-_]{60,}",
        0, 0.0, &["discord", "webhook"]);

    // ── Notion ─────────────────────────────────────────────────────────
    rule!("notion-integration-token",
        r"(?:ntn|secret)_[A-Za-z0-9]{40,}",
        0, 3.0, &["notion"]);

    // ── Supabase ───────────────────────────────────────────────────────
    rule!("supabase-service-role-key",
        r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9\-_]{30,}\.[A-Za-z0-9\-_]{30,}",
        0, 0.0, &["supabase", "service_role"]);

    // ── Vercel ─────────────────────────────────────────────────────────
    rule!("vercel-api-token",
        r#"(?i)vercel[_\s]*(?:token|key|api)\s*[:=]\s*["']?([A-Za-z0-9]{24,})["']?"#,
        1, 3.5, &["vercel"]);

    // ── HuggingFace ────────────────────────────────────────────────────
    rule!("huggingface-token",
        r"hf_[A-Za-z0-9]{30,}",
        0, 0.0, &["hf_"]);

    // ── Linear ─────────────────────────────────────────────────────────
    rule!("linear-api-key",
        r"lin_api_[A-Za-z0-9]{36,}",
        0, 0.0, &["lin_api_"]);

    // ── PEM private keys (all types) ───────────────────────────────────
    rule!("private-key-pem",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        0, 0.0, &["begin", "private key"]);

    // ── Connection strings ─────────────────────────────────────────────
    rule!("connection-string",
        r#"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s"']{10,}"#,
        0, 3.0, &["://"],
        allow: [r"(?i)localhost", r"(?i)127\.0\.0\.1", r"(?i)example\.com"]);

    // ── JWT (static tokens in source) ──────────────────────────────────
    rule!("jwt-token",
        r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}",
        0, 3.5, &["eyj"],
        allow: [r"(?i)(?:test|example|sample|mock)"]);

    // ── Generic high-entropy assignment (betterleaks generic-api-key) ──
    // Broadest catch-all. MUST use entropy + stopwords + global allowlist.
    if let Ok(regex) = Regex::new(
        r#"(?i)(?:access|auth|api|credential|creds|key|passwd|password|secret|token)\s*[:=]\s*["']([A-Za-z0-9+/\-_.=]{12,})["']"#,
    ) {
        let mut allowlist: Vec<Regex> = Vec::new();
        for pat in [
            r"(?i)(?:example|test|fake|dummy|mock|sample|placeholder|your[_\s])",
            r"^[A-Za-z]+$",
            r"^[0-9]+$",
            r"(?i)(?:true|false|null|none|undefined)",
        ] {
            if let Ok(r) = Regex::new(pat) { allowlist.push(r); }
        }
        rules.push(SecretRule {
            id: "generic-api-key",
            regex,
            secret_group: 1,
            entropy: 3.5,
            keywords: &[],
            allowlist,
            generic: true,
        });
    }

    rules
}
