#!/usr/bin/env bash
# Cross-Agent Security Report Generator
# Aggregates security scan results from multiple agents

set -euo pipefail

# Configuration
WORKSPACES=(
    "/home/suzxclaw/.openclaw/workspace-suzxclaw001-main-1"
    "/home/suzxclaw/.openclaw/workspace-suzxclaw001-main-2"
    "/home/suzxclaw/.openclaw/workspace-suzxclaw001-main-3"
    "/home/suzxclaw/.openclaw/workspace-suzxclaw001-coach"
)

REPORT_DIR="${HOME}/.openclaw/workspace/security-reports"
ALERT_FILE="${HOME}/.openclaw/workspace/security-alerts.log"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Create report directory
mkdir -p "$REPORT_DIR"

# Logging function
log() {
    local level=$1
    shift
    local msg="$*"
    echo "[$TIMESTAMP] [$level] $msg"
}

# Function to count alerts by severity for an agent
count_alerts() {
    # All agents share the same alert log file
    local alert_file="${HOME}/.openclaw/workspace/security-alerts.log"

    if [ ! -f "$alert_file" ]; then
        printf '{"HIGH": 0, "MEDIUM": 0, "LOW": 0}'
        return
    fi

    local high=$(grep "ALERT:HIGH" "$alert_file" 2>/dev/null | wc -l)
    local medium=$(grep "ALERT:MEDIUM" "$alert_file" 2>/dev/null | wc -l)
    local low=$(grep "ALERT:LOW" "$alert_file" 2>/dev/null | wc -l)

    # Ensure values are clean numbers
    high=$(echo "$high" | tr -d '[:space:]')
    medium=$(echo "$medium" | tr -d '[:space:]')
    low=$(echo "$low" | tr -d '[:space:]')

    printf '{"HIGH": %s, "MEDIUM": %s, "LOW": %s}' "$high" "$medium" "$low"
}

# Function to get latest scan time
get_last_scan() {
    # All agents share the same security log file
    local log_file="${HOME}/.openclaw/workspace/security-monitor.log"

    if [ ! -f "$log_file" ]; then
        echo "Never"
        return
    fi

    local last_scan=$(tail -1 "$log_file" | grep -oP '\[\K[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || echo "Never")
    echo "$last_scan"
}

# Function to get recent alerts for an agent
get_recent_alerts() {
    local alert_file="${HOME}/.openclaw/workspace/security-alerts.log"
    local count=${2:-5}

    if [ ! -f "$alert_file" ]; then
        return
    fi

    tail -n "$count" "$alert_file" | sed 's/^/  /'
}

# Main function to generate cross-agent report
generate_report() {
    local report_file="${REPORT_DIR}/cross-agent-report-$(date +%Y%m%d-%H%M%S).md"

    log INFO "Generating cross-agent security report..."

    cat > "$report_file" << EOF
# Cross-Agent Security Report

**Generated:** $TIMESTAMP
**Scope:** ${#WORKSPACES[@]} agent workspaces

---

## Executive Summary

EOF

    local total_high=0
    local total_medium=0
    local total_low=0

    # Collect data from all workspaces
    for ws in "${WORKSPACES[@]}"; do
        local agent_name=$(basename "$ws" | sed 's/workspace-suzxclaw001-//')
        local alerts=$(count_alerts "$ws")

        local high=$(echo "$alerts" | jq -r '.HIGH')
        local medium=$(echo "$alerts" | jq -r '.MEDIUM')
        local low=$(echo "$alerts" | jq -r '.LOW')

        total_high=$((total_high + high))
        total_medium=$((total_medium + medium))
        total_low=$((total_low + low))
    done

    # Add summary
    cat >> "$report_file" << EOF
| Metric | Count |
|--------|-------|
| 🔴 HIGH Alerts | $total_high |
| 🟡 MEDIUM Alerts | $total_medium |
| 🟢 LOW Alerts | $total_low |
| 🤖 Agents Monitored | ${#WORKSPACES[@]} |

EOF

    # Add agent-specific sections
    for ws in "${WORKSPACES[@]}"; do
        local agent_name=$(basename "$ws" | sed 's/workspace-suzxclaw001-//')
        local last_scan=$(get_last_scan "$ws")
        local alerts=$(count_alerts "$ws")

        local high=$(echo "$alerts" | jq -r '.HIGH')
        local medium=$(echo "$alerts" | jq -r '.MEDIUM')
        local low=$(echo "$alerts" | jq -r '.LOW')

        cat >> "$report_file" << EOF
---

## 🤖 Agent: $agent_name

**Last Scan:** $last_scan

### Alert Summary

| Severity | Count |
|----------|-------|
| 🔴 HIGH | $high |
| 🟡 MEDIUM | $medium |
| 🟢 LOW | $low |

### Recent Alerts

$(get_recent_alerts "$ws" 5)

EOF
    done

    # Add recommendations
    cat >> "$report_file" << EOF
---

## 📋 Recommendations

EOF

    if [ $total_high -gt 0 ]; then
        cat >> "$report_file" << EOF
### 🔴 High Priority
- Review all HIGH alerts immediately
- Investigate potential security breaches
- Update security policies if needed

EOF
    fi

    if [ $total_medium -gt 0 ]; then
        cat >> "$report_file" << EOF
### 🟡 Medium Priority
- Review MEDIUM alerts within 24 hours
- Consider if alerts are false positives
- Update baseline patterns if safe

EOF
    fi

    if [ $total_low -gt 0 ]; then
        cat >> "$report_file" << EOF
### 🟢 Low Priority
- Review LOW alerts weekly
- Monitor for trends
- Consider long-term improvements

EOF
    fi

    if [ $total_high -eq 0 ] && [ $total_medium -eq 0 ] && [ $total_low -eq 0 ]; then
        cat >> "$report_file" << EOF
✅ No security alerts detected across all agents. Great job maintaining security posture!

EOF
    fi

    # Footer
    cat >> "$report_file" << EOF
---

**Report generated by:** agent-security-monitor cross-agent-report.sh
**Next review:** 24 hours from now

EOF

    log INFO "Report saved to: $report_file"

    # Display summary to console
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Cross-Agent Security Summary${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "🤖 Agents Monitored: ${#WORKSPACES[@]}"
    echo -e "🔴 HIGH Alerts: $total_high"
    echo -e "🟡 MEDIUM Alerts: $total_medium"
    echo -e "🟢 LOW Alerts: $total_low"
    echo ""
    echo -e "Report saved to: $report_file"
    echo ""
    echo -e "${CYAN}========================================${NC}"

    # Return exit code based on alert severity
    if [ $total_high -gt 0 ]; then
        return 2  # Critical
    elif [ $total_medium -gt 0 ]; then
        return 1  # Warning
    else
        return 0  # OK
    fi
}

# Main execution
main() {
    if [ "${1:-}" = "summary" ]; then
        generate_report | grep -A 10 "## Executive Summary" | tail -9
    else
        generate_report "$@"
    fi
}

main "$@"
