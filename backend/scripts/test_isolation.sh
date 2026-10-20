#!/usr/bin/env bash
# ==============================================================================
# Bayora Docker Network Isolation Verification Script
# Validates strict 3-tier micro-segmentation:
# - Untrusted Red Team -> Broker (172.28.0.2:8000): MUST SUCCEED (HTTP 200)
# - Untrusted Red Team -> Model Worker (172.29.0.20:8001): MUST TIMEOUT / FAIL
# - Untrusted Red Team -> Blue Evaluator (172.29.0.30:8002): MUST TIMEOUT / FAIL
# ==============================================================================

set -uo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

echo -e "\n${BOLD}${CYAN}====================================================================${RESET}"
echo -e "${BOLD}${CYAN}  BAYORA PRODUCTION CONTAINER NETWORK ISOLATION AUDIT${RESET}"
echo -e "${BOLD}${CYAN}====================================================================${RESET}"

TARGET_BROKER="${BROKER_HOST:-http://broker:8000}"
TARGET_MODEL="${MODEL_WORKER_HOST:-http://model_worker:8001}"
TARGET_BLUE="${BLUE_TEAM_HOST:-http://blue_team:8002}"

TIMEOUT_SEC=3

echo -e "Auditing egress paths from container ${BOLD}$(hostname)${RESET}..."

# ------------------------------------------------------------------------------
# Test 1: Red -> Blind Broker (Mediated API Gateway)
# Expected: SUCCESS (HTTP 200)
# ------------------------------------------------------------------------------
echo -ne "\n[PROBE 1/3] Red -> Broker Gateway (${TARGET_BROKER}/v1/health)... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "${TIMEOUT_SEC}" "${TARGET_BROKER}/v1/health" 2>/dev/null || echo "000")

if [ "${HTTP_CODE}" = "200" ]; then
    echo -e "${GREEN}[ALLOWED: HTTP 200 OK]${RESET}"
    echo -e "            --> Mediated API path is active."
else
    echo -e "${RED}[FAILED: HTTP ${HTTP_CODE}]${RESET}"
    echo -e "            --> WARNING: Broker unreachable on red-broker-net."
fi

# ------------------------------------------------------------------------------
# Test 2: Red -> Model Worker (Inference Tier)
# Expected: DROP / TIMEOUT (No route across subnets)
# ------------------------------------------------------------------------------
echo -ne "\n[PROBE 2/3] Red -> Model Worker (${TARGET_MODEL}/generate)... "
WORKER_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "${TIMEOUT_SEC}" "${TARGET_MODEL}/health" 2>/dev/null || echo "TIMEOUT")

if [ "${WORKER_CODE}" = "TIMEOUT" ] || [ "${WORKER_CODE}" = "000" ]; then
    echo -e "${GREEN}[BLOCKED: PACKET DROPPED]${RESET}"
    echo -e "            --> Micro-segmentation verified: Egress to inference tier filtered."
else
    echo -e "${RED}[SECURITY LEAK: HTTP ${WORKER_CODE}]${RESET}"
    echo -e "            --> CRITICAL: Direct path to Model Worker exposed! Isolation failed."
fi

# ------------------------------------------------------------------------------
# Test 3: Red -> Blue Evaluator (Scoring Tier)
# Expected: DROP / TIMEOUT (No route across subnets)
# ------------------------------------------------------------------------------
echo -ne "\n[PROBE 3/3] Red -> Blue Evaluator (${TARGET_BLUE}/health)... "
BLUE_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "${TIMEOUT_SEC}" "${TARGET_BLUE}/health" 2>/dev/null || echo "TIMEOUT")

if [ "${BLUE_CODE}" = "TIMEOUT" ] || [ "${BLUE_CODE}" = "000" ]; then
    echo -e "${GREEN}[BLOCKED: PACKET DROPPED]${RESET}"
    echo -e "            --> Micro-segmentation verified: Egress to evaluation tier filtered."
else
    echo -e "${RED}[SECURITY LEAK: HTTP ${BLUE_CODE}]${RESET}"
    echo -e "            --> CRITICAL: Direct path to Blue Team exposed! Isolation failed."
fi

echo -e "\n${BOLD}${CYAN}--------------------------------------------------------------------${RESET}"
echo -e "${BOLD}ISOLATION AUDIT SUMMARY:${RESET}"
if [ "${HTTP_CODE}" = "200" ] && [ "${WORKER_CODE}" = "TIMEOUT" -o "${WORKER_CODE}" = "000" ] && [ "${BLUE_CODE}" = "TIMEOUT" -o "${BLUE_CODE}" = "000" ]; then
    echo -e "${GREEN}${BOLD}[PASS] Strict 3-tier container network isolation verified.${RESET}"
    echo -e "       Untrusted adversarial runners have ZERO direct routes to protected workloads."
else
    echo -e "${RED}${BOLD}[FAIL] Container network configuration violated.${RESET}"
fi
echo -e "${BOLD}${CYAN}====================================================================${RESET}\n"
