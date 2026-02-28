#!/bin/bash

################################################################################
# AWS Macie S3 Sensitive Data Detection and Encryption Script
# 
# Purpose: Detect sensitive information in S3 buckets using AWS Macie and
#          automatically encrypt detected sensitive objects
#
# Prerequisites:
#   - AWS CLI installed and configured with appropriate credentials
#   - IAM permissions for Macie, S3, KMS, and CloudWatch Logs
#   - jq for JSON parsing (optional)
#
# Usage:
#   ./aws_macie_s3_encrypt.sh [OPTIONS]
#   ./aws_macie_s3_encrypt.sh --bucket my-bucket --kms-key-id arn:aws:kms...
#   ./aws_macie_s3_encrypt.sh --enable-macie --create-job --bucket my-bucket
################################################################################

set -euo pipefail

# Configuration
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly LOG_FILE="${LOG_DIR}/macie_$(date +%Y%m%d_%H%M%S).log"
readonly CONFIG_FILE="${SCRIPT_DIR}/macie_config.json"

# Default values
MACIE_ENABLED=false
CREATE_JOB=false
ENCRYPT_FINDINGS=false
BUCKET_NAME=""
KMS_KEY_ID=""
CLASSIFICATION_DETAIL_LEVEL="full"
JOB_NAME_PREFIX="sensitive-data-scan"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Logging Functions
################################################################################

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "${LOG_FILE}"
}

################################################################################
# Setup Functions
################################################################################

setup_logging() {
    mkdir -p "${LOG_DIR}" || {
        echo "Failed to create log directory: ${LOG_DIR}"
        exit 1
    }
    log_info "Logging initialized. Log file: ${LOG_FILE}"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    log_success "AWS CLI found: $(aws --version)"
    
    # Check jq (optional but recommended)
    if ! command -v jq &> /dev/null; then
        log_warning "jq is not installed. Some features may be limited. Install with: sudo apt-get install jq"
    else
        log_success "jq found: $(jq --version)"
    fi
    
    # Test AWS credentials
    if ! aws sts get-caller-identity --region "${AWS_REGION}" &> /dev/null; then
        log_error "AWS credentials not configured or invalid."
        exit 1
    fi
    log_success "AWS credentials are valid"
}

################################################################################
# Macie Management Functions
################################################################################

enable_macie() {
    log_info "Enabling AWS Macie..."
    
    if aws macie2 enable-macie --region "${AWS_REGION}" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "AWS Macie enabled successfully"
        return 0
    elif grep -q "Macie is already enabled" <<< "$(aws macie2 enable-macie --region "${AWS_REGION}" 2>&1)"; then
        log_info "Macie is already enabled"
        return 0
    else
        log_error "Failed to enable Macie"
        return 1
    fi
}

get_macie_status() {
    log_info "Checking Macie status..."
    
    local status
    status=$(aws macie2 get-macie-session --region "${AWS_REGION}" 2>&1) || {
        log_error "Macie is not enabled"
        return 1
    }
    
    echo "${status}" | tee -a "${LOG_FILE}"
    log_success "Macie status retrieved"
}

enable_s3_classification() {
    log_info "Enabling S3 classification for bucket: ${BUCKET_NAME}..."
    
    if aws macie2 enable-organization-admin-account \
        --admin-account-id "$(aws sts get-caller-identity --query Account --output text)" \
        --region "${AWS_REGION}" 2>&1 | tee -a "${LOG_FILE}"; then
        log_success "S3 classification enabled"
    else
        log_warning "S3 classification may already be enabled"
    fi
}

################################################################################
# Macie Job Functions
################################################################################

create_macie_job() {
    log_info "Creating AWS Macie scan job for bucket: ${BUCKET_NAME}..."
    
    local job_name="${JOB_NAME_PREFIX}-$(date +%s)"
    local job_config
    
    # Create job configuration
    cat > /tmp/macie_job.json <<EOF
{
    "bucketDefinitions": [
        {
            "accountId": "$(aws sts get-caller-identity --query Account --output text)",
            "buckets": ["${BUCKET_NAME}"]
        }
    ],
    "jobType": "DISCOVERY_JOB",
    "name": "${job_name}",
    "description": "Automated scan for sensitive data in ${BUCKET_NAME}",
    "s3JobDefinition": {
        "bucketDefinitions": [
            {
                "accountId": "$(aws sts get-caller-identity --query Account --output text)",
                "buckets": ["${BUCKET_NAME}"]
            }
        ],
        "scoping": {
            "includes": {
                "and": []
            }
        }
    },
    "samplingPercentage": 100,
    "scheduleFrequency": {
        "dailySchedule": {}
    },
    "initialRun": true
}
EOF
    
    local job_id
    job_id=$(aws macie2 create-classification-job \
        --bucket-definitions bucketDefinitions=@/tmp/macie_job.json \
        --job-type DISCOVERY_JOB \
        --name "${job_name}" \
        --description "Scan for sensitive data in ${BUCKET_NAME}" \
        --managed-data-identifier-selector ALL \
        --region "${AWS_REGION}" \
        --query 'jobId' \
        --output text 2>&1) || {
        log_error "Failed to create Macie job"
        rm -f /tmp/macie_job.json
        return 1
    }
    
    rm -f /tmp/macie_job.json
    log_success "Macie job created successfully. Job ID: ${job_id}"
    echo "${job_id}"
}

list_macie_jobs() {
    log_info "Listing Macie jobs..."
    
    aws macie2 list-classification-jobs \
        --region "${AWS_REGION}" \
        --query 'items[*].[jobId,name,jobStatus]' \
        --output table | tee -a "${LOG_FILE}"
}

get_job_findings() {
    local job_id=$1
    log_info "Retrieving findings for job: ${job_id}..."
    
    aws macie2 list-findings \
        --region "${AWS_REGION}" \
        --query "findings[?resourcesAffected.s3Object.bucketName=='${BUCKET_NAME}']" \
        --output json | tee -a "${LOG_FILE}"
}

################################################################################
# Encryption Functions
################################################################################

encrypt_s3_object() {
    local bucket=$1
    local key=$2
    local kms_key=$3
    
    log_info "Encrypting object: s3://${bucket}/${key}"
    
    if [ -z "${kms_key}" ]; then
        # Use SSE-S3 (AES-256)
        if aws s3api copy-object \
            --bucket "${bucket}" \
            --copy-source "${bucket}/${key}" \
            --key "${key}" \
            --server-side-encryption AES256 \
            --region "${AWS_REGION}" &>> "${LOG_FILE}"; then
            log_success "Object encrypted with SSE-S3: s3://${bucket}/${key}"
            return 0
        fi
    else
        # Use SSE-KMS with customer key
        if aws s3api copy-object \
            --bucket "${bucket}" \
            --copy-source "${bucket}/${key}" \
            --key "${key}" \
            --server-side-encryption aws:kms \
            --ssekms-key-id "${kms_key}" \
            --region "${AWS_REGION}" &>> "${LOG_FILE}"; then
            log_success "Object encrypted with KMS: s3://${bucket}/${key}"
            return 0
        fi
    fi
    
    log_error "Failed to encrypt object: s3://${bucket}/${key}"
    return 1
}

enable_bucket_encryption() {
    local bucket=$1
    local kms_key=$2
    
    log_info "Enabling default encryption for bucket: ${bucket}..."
    
    if [ -z "${kms_key}" ]; then
        # Use SSE-S3
        local rule='{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}'
    else
        # Use SSE-KMS
        local rule="{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"${kms_key}\"}}"
    fi
    
    if aws s3api put-bucket-encryption \
        --bucket "${bucket}" \
        --server-side-encryption-configuration "{\"Rules\":[${rule}]}" \
        --region "${AWS_REGION}" &>> "${LOG_FILE}"; then
        log_success "Default encryption enabled for bucket: ${bucket}"
        return 0
    else
        log_error "Failed to enable encryption for bucket: ${bucket}"
        return 1
    fi
}

enable_bucket_versioning() {
    local bucket=$1
    
    log_info "Enabling versioning for bucket: ${bucket}..."
    
    if aws s3api put-bucket-versioning \
        --bucket "${bucket}" \
        --versioning-configuration Status=Enabled \
        --region "${AWS_REGION}" &>> "${LOG_FILE}"; then
        log_success "Versioning enabled for bucket: ${bucket}"
        return 0
    else
        log_error "Failed to enable versioning for bucket: ${bucket}"
        return 1
    fi
}

encrypt_bucket_objects() {
    local bucket=$1
    local kms_key=${2:-}
    
    log_info "Encrypting all unencrypted objects in bucket: ${bucket}..."
    
    local count=0
    local error_count=0
    
    # List all unencrypted objects
    aws s3api list-objects-v2 \
        --bucket "${bucket}" \
        --region "${AWS_REGION}" \
        --query 'Contents[*].Key' \
        --output text | while read -r key; do
        
        # Check if object is encrypted
        local encryption_status
        encryption_status=$(aws s3api head-object \
            --bucket "${bucket}" \
            --key "${key}" \
            --region "${AWS_REGION}" \
            --query 'ServerSideEncryption' \
            --output text 2>/dev/null || echo "NONE")
        
        if [ "${encryption_status}" = "NONE" ]; then
            if encrypt_s3_object "${bucket}" "${key}" "${kms_key}"; then
                ((count++)) || true
            else
                ((error_count++)) || true
            fi
        fi
    done
    
    log_info "Encryption process completed. Encrypted: ${count}, Errors: ${error_count}"
}

################################################################################
# Remediation Functions
################################################################################

remediate_findings() {
    log_info "Starting remediation process..."
    
    if [ -z "${BUCKET_NAME}" ]; then
        log_error "Bucket name not specified for remediation"
        return 1
    fi
    
    # Enable bucket-level encryption
    enable_bucket_encryption "${BUCKET_NAME}" "${KMS_KEY_ID}"
    
    # Enable versioning for additional protection
    enable_bucket_versioning "${BUCKET_NAME}"
    
    # Encrypt all objects
    encrypt_bucket_objects "${BUCKET_NAME}" "${KMS_KEY_ID}"
    
    log_success "Remediation process completed for bucket: ${BUCKET_NAME}"
}

################################################################################
# Reporting Functions
################################################################################

generate_report() {
    local bucket=$1
    local report_file="${LOG_DIR}/macie_report_$(date +%Y%m%d_%H%M%S).json"
    
    log_info "Generating remediation report..."
    
    cat > "${report_file}" <<EOF
{
    "reportDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "bucket": "${bucket}",
    "region": "${AWS_REGION}",
    "accountId": "$(aws sts get-caller-identity --query Account --output text)",
    "encryptionStatus": $(aws s3api get-bucket-encryption --bucket "${bucket}" --region "${AWS_REGION}" 2>/dev/null || echo '{}'),
    "versioningStatus": $(aws s3api get-bucket-versioning --bucket "${bucket}" --region "${AWS_REGION}" --query '{Status:Status,MFADelete:MFADelete}' --output json 2>/dev/null || echo '{}'),
    "bucketPolicy": $(aws s3api get-bucket-policy --bucket "${bucket}" --region "${AWS_REGION}" --query 'Policy' --output json 2>/dev/null || echo '{}')
}
EOF
    
    log_success "Report generated: ${report_file}"
    cat "${report_file}" | tee -a "${LOG_FILE}"
}

################################################################################
# Usage and Help
################################################################################

show_usage() {
    cat << EOF
${GREEN}AWS Macie S3 Sensitive Data Detection and Encryption${NC}

${BLUE}Usage:${NC}
    ${SCRIPT_NAME} [OPTIONS]

${BLUE}Options:${NC}
    -b, --bucket <BUCKET_NAME>          S3 bucket name to scan and encrypt
    -k, --kms-key-id <KEY_ID>           KMS key ID for encryption (optional)
                                        If not provided, SSE-S3 will be used
    -e, --enable-macie                  Enable AWS Macie
    -j, --create-job                    Create a new Macie scan job
    -r, --remediate                     Enable encryption and remediate findings
    -l, --list-jobs                     List all Macie jobs
    -g, --generate-report               Generate security report
    -s, --status                        Show Macie status
    -h, --help                          Show this help message

${BLUE}Examples:${NC}
    # Enable Macie
    ${SCRIPT_NAME} --enable-macie

    # Create a scan job for a bucket
    ${SCRIPT_NAME} --bucket my-bucket --create-job

    # Enable encryption and remediate findings
    ${SCRIPT_NAME} --bucket my-bucket --remediate

    # Use KMS encryption
    ${SCRIPT_NAME} --bucket my-bucket --kms-key-id arn:aws:kms:us-east-1:123456789:key/abc123 --remediate

    # Full workflow
    ${SCRIPT_NAME} --enable-macie --bucket my-bucket --create-job --remediate

${BLUE}Environment Variables:${NC}
    AWS_REGION              AWS region (default: us-east-1)
    AWS_PROFILE             AWS profile to use

EOF
}

################################################################################
# Main Function
################################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -b|--bucket)
                BUCKET_NAME="$2"
                shift 2
                ;;
            -k|--kms-key-id)
                KMS_KEY_ID="$2"
                shift 2
                ;;
            -e|--enable-macie)
                MACIE_ENABLED=true
                shift
                ;;
            -j|--create-job)
                CREATE_JOB=true
                shift
                ;;
            -r|--remediate)
                ENCRYPT_FINDINGS=true
                shift
                ;;
            -l|--list-jobs)
                setup_logging
                check_prerequisites
                list_macie_jobs
                exit 0
                ;;
            -s|--status)
                setup_logging
                check_prerequisites
                get_macie_status
                exit 0
                ;;
            -g|--generate-report)
                if [ -z "${BUCKET_NAME}" ]; then
                    log_error "Bucket name is required for report generation"
                    show_usage
                    exit 1
                fi
                setup_logging
                check_prerequisites
                generate_report "${BUCKET_NAME}"
                exit 0
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Initialize
    setup_logging
    check_prerequisites
    
    log_info "Starting AWS Macie S3 Sensitive Data Detection and Encryption"
    log_info "Configuration: Bucket=${BUCKET_NAME}, KMS Key=${KMS_KEY_ID}, Region=${AWS_REGION}"
    
    # Execute selected operations
    if [ "${MACIE_ENABLED}" = true ]; then
        enable_macie
    fi
    
    if [ "${CREATE_JOB}" = true ]; then
        if [ -z "${BUCKET_NAME}" ]; then
            log_error "Bucket name is required to create a Macie job"
            show_usage
            exit 1
        fi
        create_macie_job
    fi
    
    if [ "${ENCRYPT_FINDINGS}" = true ]; then
        if [ -z "${BUCKET_NAME}" ]; then
            log_error "Bucket name is required for remediation"
            show_usage
            exit 1
        fi
        remediate_findings
        generate_report "${BUCKET_NAME}"
    fi
    
    if [[ "${MACIE_ENABLED}" = false && "${CREATE_JOB}" = false && "${ENCRYPT_FINDINGS}" = false ]]; then
        log_info "No operations specified. Use --help for usage information"
        show_usage
        exit 0
    fi
    
    log_success "Script execution completed successfully"
    log_info "Logs available at: ${LOG_FILE}"
}

# Run main function
main "$@"
