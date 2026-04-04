<h1 align="center">gas-check</h1>

<p align="center">
  Google Apps Script governance verification CLI.
</p>

<p align="center">
  <a href="https://github.com/HikaruEgashira/libverify">libverify</a>
</p>

---

[![CI](https://github.com/HikaruEgashira/gas-check/actions/workflows/ci.yml/badge.svg)](https://github.com/HikaruEgashira/gas-check/actions/workflows/ci.yml)

gas-check evaluates the security, compliance, and best-practice posture of Google Apps Script projects through 18 domain-specific controls. It checks sharing settings, OAuth scopes, deployment hygiene, secret leakage, and more.

Powered by [libverify](https://github.com/HikaruEgashira/libverify).

> [!NOTE]
>
> gas-check follows semver. The 0.x series may introduce breaking changes between minor versions.

## Quick Start

```bash
# 1. Install (download binary from releases)
curl -LO https://github.com/HikaruEgashira/gas-check/releases/latest/download/gas-check-aarch64-apple-darwin.tar.gz
tar xzf gas-check-aarch64-apple-darwin.tar.gz
sudo mv gas-check /usr/local/bin/

# 2. Authenticate via clasp (uses ~/.clasprc.json)
npx @google/clasp login

# 3. Verify a GAS project
gas-check project <script-id>
```

## Usage

```bash
# Verify a GAS project's governance posture
gas-check project <script-id>

# List available controls
gas-check controls

# List available policy presets
gas-check policies

# Output formats: human (default), json, sarif
gas-check project <script-id> --format json
gas-check project <script-id> --format sarif

# Policy presets
gas-check project <script-id> --policy gas-default
gas-check project <script-id> --policy gas-strict

# Custom OPA policy file
gas-check project <script-id> --policy path/to/custom.rego

# Show only failures
gas-check project <script-id> --only-failures

# Include raw evidence in JSON output
gas-check project <script-id> --format json --with-evidence

# Quiet mode: suppress progress messages
gas-check project <script-id> --quiet
```

Exit codes: `0` = all controls pass, `1` = verification found failures or items requiring review, `2` = runtime error.

## Controls

gas-check includes 18 GAS-specific controls:

| Control | Description |
|---------|-------------|
| `gas-sharing-restriction` | Validates project sharing settings |
| `gas-editor-count-audit` | Checks the number of editors is reasonable |
| `gas-oauth-scope-minimization` | Ensures OAuth scopes follow least-privilege |
| `gas-version-hygiene` | Validates version management practices |
| `gas-deployment-version-linkage` | Verifies deployments link to specific versions |
| `gas-description-quality` | Checks project description completeness |
| `gas-trigger-audit` | Audits installed triggers for risks |
| `gas-external-library-audit` | Reviews external library dependencies |
| `gas-gcp-project-linkage` | Validates GCP project association |
| `gas-library-inventory` | Inventories library dependencies |
| `gas-manifest-integrity` | Checks appsscript.json manifest integrity |
| `gas-webapp-access-control` | Validates web app access settings |
| `gas-api-executable-access` | Checks API executable access controls |
| `gas-head-drift` | Detects unversioned HEAD changes in the editor |
| `gas-secret-scanning` | Scans source for hardcoded secrets (API keys, tokens, passwords) |
| `gas-edit-source-detection` | Detects whether code was pushed via clasp or edited manually |
| `gas-version-history-integrity` | Checks version history for sequential numbering and monotonic timestamps |
| `gas-stale-deployment` | Detects deployments pointing to versions 2+ behind the latest |

## Policy Presets

| Preset | Description |
|--------|-------------|
| `default` | Built-in libverify default (all controls strict) |
| `gas-default` | GAS-tuned defaults (balanced severity) |
| `gas-strict` | All GAS controls fail on violation |
| `oss` | Tolerant for open-source projects |
| `soc2` | SOC2 Trust Services mapping |

## License

[MIT](LICENSE)
