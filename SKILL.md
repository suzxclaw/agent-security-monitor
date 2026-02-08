---
name: agent-security-monitor
description: Security monitoring and alerting tool for AI agents. Automatically checks for exposed secrets, unverified skills, insecure keys, suspicious commands, and malicious patterns. Provides color-coded output and comprehensive alerting.
metadata:
  requires_bins: []
  install:
    - id: node
      kind: node
      package: bash
  version: 1.0.0
tags: security, monitoring, agent, cybersecurity, safety
---

# Agent Security Monitor

A comprehensive security monitoring and alerting tool for AI agents running on OpenClaw.

## What It Does

Automatically scans your agent environment for security vulnerabilities and suspicious activity:

1. **Exposed Secrets Detection**
   - Scans `.env` files and `secrets.*` files for sensitive patterns
   - Checks if secrets are properly masked (placeholder patterns like `your_key`, `xxxx`)
   - Alerts on potential secret leaks

2. **Unverified Skills Detection**
   - Identifies skills without `SKILL.md` documentation
   - Scans skill files for suspicious patterns (`webhook.site`, `curl .`, `eval()`, etc.)
   - Warns about potentially malicious code

3. **SSH Key Security**
   - Checks SSH key files for correct permissions (should be 600 or 400)
   - Detects insecure key storage

4. **Command History Monitoring**
   - Scans recent command history for suspicious patterns
   - Alerts on `.env` file manipulation or suspicious `chmod` commands

5. **Log File Protection**
   - Scans log files for sensitive data leaks
   - Checks for `Bearer` tokens, API keys, passwords

6. **Git Repository Safety**
   - Detects if secrets have been committed to git repositories

## Features

- ✅ **No external dependencies** - Pure Bash, runs everywhere
- ✅ **Configurable** - JSON-based configuration for custom checks
- ✅ **Color-coded output** - GREEN (info), YELLOW (medium alert), RED (high alert)
- ✅ **Comprehensive logging** - All scans and alerts recorded to log files
- ✅ **Smart detection** - Distinguishes between real secrets and placeholder patterns
- ✅ **Baseline tracking** - Remembers when last scan was performed

## Installation

1. Copy this skill to your OpenClaw workspace:
   ```bash
   mkdir -p ~/openclaw/workspace/skills/agent-security-monitor
   ```

2. Run the monitor:
   ```bash
   ~/openclaw/workspace/skills/agent-security-monitor/scripts/security-monitor.sh
   ```

## Usage

```bash
# Basic scan
security-monitor.sh

# Check status
security-monitor.sh status

# Show recent alerts
tail -20 ~/openclaw/workspace/security-alerts.log
```

## Configuration

The monitor creates a configuration file at `~/.config/agent-security/config.json` with the following structure:

```json
{
  "checks": {
    "env_files": true,
    "api_keys": true,
    "ssh_keys": true,
    "unverified_skills": true,
    "log_sanitization": true
  },
  "alerts": {
    "email": false,
    "log_file": true,
    "moltbook_post": false
  }
}
```

## Log Files

- **Security Log**: `~/openclaw/workspace/security-monitor.log` - All scan results and status
- **Alerts Log**: `~/openclaw/workspace/security-alerts.log` - High and medium alerts only

## What It Protects Against

- 🚨 **Credential exfiltration** - Detects `.env` files containing exposed API keys
- 🐍 **Supply chain attacks** - Identifies suspicious patterns in installed skills
- 🔑 **Key theft** - Monitors SSH keys and wallet credentials
- 💀 **Malicious execution** - Scans for suspicious command patterns
- 📝 **Data leaks** - Prevents sensitive information from appearing in logs

## Best Practices

1. **Run regularly** - Schedule this monitor to run daily or weekly
2. **Review alerts** - Check `security-alerts.log` frequently
3. **Update configuration** - Customize which checks to enable/disable
4. **Keep secrets protected** - Use `~/.openclaw/secrets/` with 700 permissions
5. **Verify before install** - Always review skill code before installing new skills

## Technical Details

- **Language**: Bash (POSIX compliant)
- **Dependencies**: None (uses only standard Unix tools: `jq`, `grep`, `find`, `stat`)
- **Size**: ~9KB script
- **Platforms**: Linux, macOS (with minor adaptations)

## Version History

- **1.0.0** (2026-02-08) - Initial release
  - Basic security monitoring
  - Alert logging system
  - Color-coded output
  - Configuration file support

---

*Built by Claw (suzxclaw) - AI Security Specialist*
*License: MIT*
