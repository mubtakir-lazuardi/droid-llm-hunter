#!/bin/bash
# ==============================================================================
# Droid-LLM-Hunter GitHub Action Entrypoint
# ==============================================================================
# This script handles the initialization and execution of the security scan
# within the Docker environment. It manages path resolution between the
# GitHub Runner Workspace and the Docker Container filesystem.
# ==============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Function to log messages with timestamps
log_info() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1"
}

log_info "Starting Droid-LLM-Hunter Action..."

# 1. Configure Settings
# ===================
# Injects CI environment variables into the internal YAML configuration.
if ! python3 /app/scripts/ci/configurator.py; then
   log_error "Configuration failed. Please check your inputs and API keys."
   exit 1
fi

# 2. Prepare Execution Environment
# ==============================
cd /app || { log_error "Failed to change directory to /app"; exit 1; }

# 3. Path Resolution
# =================
# Resolve the APK path relative to the GitHub Workspace mounting point.
WORKSPACE=${GITHUB_WORKSPACE:-/github/workspace}
RAW_APK_PATH="${INPUT_APK_PATH}"

if [ -z "$RAW_APK_PATH" ]; then
    log_error "Input 'apk-path' is required but was not provided."
    exit 1
fi

# Determine absolute path
if [[ "$RAW_APK_PATH" != /* ]]; then
    FULL_APK_PATH="$WORKSPACE/$RAW_APK_PATH"
else
    FULL_APK_PATH="$RAW_APK_PATH"
fi

log_info "Target APK: $FULL_APK_PATH"

if [ ! -f "$FULL_APK_PATH" ]; then
    log_error "APK file not found at: $FULL_APK_PATH"
    
    log_info "---------------- DEBUG INFO ----------------"
    log_info "Current User: $(whoami) (UID: $(id -u))"
    log_info "Workspace Mount ($WORKSPACE) permissions:"
    ls -ld "$WORKSPACE"
    
    log_info "Searching for any .apk files in workspace (maxdepth 6)..."
    FOUND_APKS=$(find "$WORKSPACE" -maxdepth 6 -name "*.apk")
    
    if [ -z "$FOUND_APKS" ]; then
        log_error "No APK files found anywhere in the workspace! configure your 'Build' step correctly?"
    else
        log_info "Found the following APK candidates:"
        echo "$FOUND_APKS"
        log_info "Please update your 'apk-path' input to match one of the above."
    fi
    log_info "--------------------------------------------"
    exit 1
fi

# 4. Execute Scan
# =================
OUTPUT_FILE="$WORKSPACE/droid-llm-report.json"
FAILED_EXIT_CODE=0

log_info "Running Droid-LLM-Hunter scan..."

# Note: We capture the exit status. Currently dlh.py returns 0 even on findings,
# but we prepare this logic for future strict modes.
if python3 dlh.py --output "$OUTPUT_FILE" scan "$FULL_APK_PATH"; then
    log_info "Scan completed successfully."
else
    log_error "Scan failed to complete due to an internal error."
    exit 1
fi

log_info "Report saved to: $OUTPUT_FILE"

