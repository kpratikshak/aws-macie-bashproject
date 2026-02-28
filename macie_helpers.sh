#!/bin/bash

################################################################################
# AWS Macie Helper Utilities
# 
# Purpose: Provides additional utilities for managing and monitoring Macie
#          and S3 bucket security
#
# Usage:
#   ./macie_helpers.sh [COMMAND] [OPTIONS]
#
################################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
AWS_REGION="${AWS_REGION:-us-east-1}"

################################################################################
# Utility Functions
################################################################################

print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $*"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $*"
}

print_error() {
    echo -e "${RED}✗${NC} $*"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $*"
}

################################################################################
# Bucket Analysis
################################################################################

analyze_bucket_security() {
    local bucket=$1
    
    print_header "Analyzing Security Configuration for: $bucket"
    
    echo -e "${BLUE}[1] Encryption Status${NC}"
    if aws s3api get-bucket-encryption --bucket "$bucket" --region "$AWS_REGION" &>/dev/null; then
        encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --region "$AWS_REGION" --output json)
        echo "$encryption" | jq '.' 2>/dev/null || echo "$encryption"
        print_success "Encryption enabled"
    else
        print_warning "No default encryption configured"
    fi
    
    echo -e "\n${BLUE}[2] Versioning Status${NC}"
    versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" --region "$AWS_REGION" --output json)
    echo "$versioning" | jq '.' 2>/dev/null || echo "$versioning"
    
    echo -e "\n${BLUE}[3] Public Access Block${NC}"
    if aws s3api get-public-access-block --bucket "$bucket" --region "$AWS_REGION" &>/dev/null; then
        pab=$(aws s3api get-public-access-block --bucket "$bucket" --region "$AWS_REGION" --output json)
        echo "$pab" | jq '.PublicAccessBlockConfiguration' 2>/dev/null || echo "$pab"
        print_success "Public access block configured"
    else
        print_warning "No public access block configured"
    fi
    
    echo -e "\n${BLUE}[4] Bucket Policy${NC}"
    if aws s3api get-bucket-policy --bucket "$bucket" --region "$AWS_REGION" &>/dev/null; then
        print_success "Bucket policy exists"
        # Show policy summary only, not full policy
        aws s3api get-bucket-policy --bucket "$bucket" --region "$AWS_REGION}" --output json | jq '.Policy | fromjson | .Statement[].Effect' 2>/dev/null | sort | uniq -c
    else
        print_warning "No bucket policy found"
    fi
    
    echo -e "\n${BLUE}[5] Bucket Logging${NC}"
    if aws s3api get-bucket-logging --bucket "$bucket" --region "$AWS_REGION" &>/dev/null; then
        print_success "Logging enabled"
        aws s3api get-bucket-logging --bucket "$bucket" --region "$AWS_REGION" --output json | jq '.LoggingEnabled' 2>/dev/null || echo "Logging status: enabled"
    else
        print_warning "Logging not enabled"
    fi
    
    echo -e "\n${BLUE}[6] Object Count and Size${NC}"
    object_count=$(aws s3api list-objects-v2 --bucket "$bucket" --region "$AWS_REGION" --query 'KeyCount' --output text)
    total_size=$(aws s3api list-objects-v2 --bucket "$bucket" --region "$AWS_REGION" --query 'Contents[].Size' --output text | awk '{sum+=$1} END {print sum}')
    
    echo -e "Total objects: ${GREEN}$object_count${NC}"
    echo -e "Total size: ${GREEN}$(numfmt --to=iec-i --suffix=B $total_size 2>/dev/null || echo $total_size bytes)${NC}"
    
    echo -e "\n${BLUE}[7] Encryption Summary${NC}"
    encrypted=0
    unencrypted=0
    
    aws s3api list-objects-v2 --bucket "$bucket" --region "$AWS_REGION" --query 'Contents[*].Key' --output text | head -100 | while read -r key; do
        encryption=$(aws s3api head-object --bucket "$bucket" --key "$key" --region "$AWS_REGION}" --query 'ServerSideEncryption' --output text 2>/dev/null || echo "NONE")
        if [ "$encryption" != "NONE" ]; then
            ((encrypted++)) || true
        else
            ((unencrypted++)) || true
        fi
    done
    
    print_success "Analysis complete"
}

################################################################################
# Compliance Checks
################################################################################

run_compliance_checks() {
    local bucket=$1
    
    print_header "Running Compliance Checks for: $bucket"
    
    local passed=0
    local failed=0
    
    # Check 1: Default encryption enabled
    if aws s3api get-bucket-encryption --bucket "$bucket" --region "$AWS_REGION" &>/dev/null; then
        print_success "[PASS] Default encryption is enabled"
        ((passed++)) || true
    else
        print_error "[FAIL] Default encryption is NOT enabled"
        ((failed++)) || true
    fi
    
    # Check 2: Versioning enabled
    versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" --region "$AWS_REGION" --query 'Status' --output text 2>/dev/null || echo "NONE")
    if [ "$versioning" = "Enabled" ]; then
        print_success "[PASS] Versioning is enabled"
        ((passed++)) || true
    else
        print_warning "[WARN] Versioning is not enabled (recommended for production)"
        ((failed++)) || true
    fi
    
    # Check 3: Block public access
    pab=$(aws s3api get-public-access-block --bucket "$bucket" --region "$AWS_REGION" --query 'PublicAccessBlockConfiguration.BlockPublicAcls' --output text 2>/dev/null || echo "false")
    if [ "$pab" = "true" ] || [ "$pab" = "True" ]; then
        print_success "[PASS] Public access is blocked"
        ((passed++)) || true
    else
        print_error "[FAIL] Public access is NOT blocked"
        ((failed++)) || true
    fi
    
    # Check 4: Server Access Logging
    logging=$(aws s3api get-bucket-logging --bucket "$bucket" --region "$AWS_REGION" 2>/dev/null || echo "{}")
    if echo "$logging" | grep -q "LoggingEnabled" 2>/dev/null; then
        print_success "[PASS] Server access logging is configured"
        ((passed++)) || true
    else
        print_warning "[WARN] Server access logging is NOT configured"
        ((failed++)) || true
    fi
    
    # Check 5: Bucket Policy enforces encryption
    policy=$(aws s3api get-bucket-policy --bucket "$bucket" --region "$AWS_REGION" --query 'Policy' --output text 2>/dev/null || echo "{}")
    if echo "$policy" | grep -q "s3:x-amz-server-side-encryption" 2>/dev/null; then
        print_success "[PASS] Bucket policy enforces encryption"
        ((passed++)) || true
    else
        print_warning "[WARN] Bucket policy does NOT enforce encryption"
        ((failed++)) || true
    fi
    
    # Summary
    echo -e "\n${BLUE}Summary:${NC}"
    echo -e "Passed: ${GREEN}$passed${NC}"
    echo -e "Failed/Warnings: ${YELLOW}$failed${NC}"
    
    if [ $failed -eq 0 ]; then
        print_success "All checks passed!"
    fi
}

################################################################################
# Cost Estimation
################################################################################

estimate_macie_costs() {
    local bucket=$1
    
    print_header "Estimating Macie Costs for: $bucket"
    
    # Get bucket metrics
    object_count=$(aws s3api list-objects-v2 --bucket "$bucket" --region "$AWS_REGION" --query 'KeyCount' --output text 2>/dev/null || echo 0)
    total_size=$(aws s3api list-objects-v2 --bucket "$bucket" --region "$AWS_REGION" --query 'Contents[].Size' --output text | awk '{sum+=$1} END {print sum}' 2>/dev/null || echo 0)
    
    echo -e "${CYAN}Bucket Metrics:${NC}"
    echo -e "Objects: ${GREEN}$object_count${NC}"
    echo -e "Total Size: ${GREEN}$(numfmt --to=iec-i --suffix=B $total_size 2>/dev/null || echo $total_size bytes)${NC}"
    
    # Calculate Macie costs
    bucket_cost=1  # $1 per bucket per month
    object_cost=$(echo "scale=2; $object_count / 1000 * 0.35" | bc 2>/dev/null || echo "0")
    analysis_cost=$(echo "scale=2; $total_size / 1024 / 1024 / 1024 * 0.30" | bc 2>/dev/null || echo "0")
    
    total_macie_cost=$(echo "scale=2; $bucket_cost + $object_cost + $analysis_cost" | bc 2>/dev/null || echo "0")
    
    echo -e "\n${CYAN}Macie Cost Breakdown (per month):${NC}"
    echo -e "Bucket fee: ${GREEN}\$$bucket_cost${NC}"
    echo -e "Object assessment (~0.35 per 1000): ${GREEN}\$$object_cost${NC}"
    echo -e "Data scanning (~0.30 per GB): ${GREEN}\$$analysis_cost${NC}"
    echo -e "Annual Macie cost: ${YELLOW}\$$(echo "scale=2; $total_macie_cost * 12" | bc 2>/dev/null || echo "0")${NC}"
    
    # KMS costs (if using KMS)
    echo -e "\n${CYAN}KMS Cost Estimate (if using customer keys):${NC}"
    kms_key_cost=1  # $1 per key per month
    kms_api_cost=$(echo "scale=2; $object_count / 100000 * 0.03" | bc 2>/dev/null || echo "0")  # 0.03 per 10k API calls
    total_kms_cost=$(echo "scale=2; $kms_key_cost + $kms_api_cost" | bc 2>/dev/null || echo "0")
    
    echo -e "Key storage fee: ${GREEN}\$$kms_key_cost${NC}"
    echo -e "API calls (~0.03 per 10k): ${GREEN}\$$kms_api_cost${NC}"
    echo -e "Annual KMS cost: ${YELLOW}\$$(echo "scale=2; $total_kms_cost * 12" | bc 2>/dev/null || echo "0")${NC}"
    
    echo -e "\n${CYAN}Total Annual Cost (Macie + KMS):${NC}"
    total_cost=$(echo "scale=2; ($total_macie_cost + $total_kms_cost) * 12" | bc 2>/dev/null || echo "0")
    echo -e "${YELLOW}\$$total_cost${NC}"
}

################################################################################
# Find Unencrypted Objects
################################################################################

find_unencrypted_objects() {
    local bucket=$1
    local output_file="${SCRIPT_DIR}/unencrypted_objects_$(date +%s).txt"
    
    print_header "Finding Unencrypted Objects in: $bucket"
    
    unencrypted_count=0
    
    echo "Scanning all objects... (this may take a while)"
    echo "Results will be saved to: $output_file"
    
    aws s3api list-objects-v2 \
        --bucket "$bucket" \
        --region "$AWS_REGION" \
        --query 'Contents[*].Key' \
        --output text | tr '\t' '\n' | while read -r key; do
        
        [ -z "$key" ] && continue
        
        encryption=$(aws s3api head-object \
            --bucket "$bucket" \
            --key "$key" \
            --region "$AWS_REGION" \
            --query 'ServerSideEncryption' \
            --output text 2>/dev/null || echo "NONE")
        
        if [ "$encryption" = "NONE" ]; then
            echo "$key" >> "$output_file"
            ((unencrypted_count++)) || true
            if [ $((unencrypted_count % 100)) -eq 0 ]; then
                print_info "Found $unencrypted_count unencrypted objects..."
            fi
        fi
    done
    
    print_success "Scan complete. Found $unencrypted_count unencrypted objects"
    print_info "Details saved to: $output_file"
}

################################################################################
# Macie Findings Summary
################################################################################

get_findings_summary() {
    print_header "Macie Findings Summary"
    
    # Get findings summary (requires Macie to be enabled)
    if ! aws macie2 get-macie-session --region "$AWS_REGION" &>/dev/null; then
        print_error "Macie is not enabled in this account"
        return 1
    fi
    
    echo -e "${CYAN}Recent Findings:${NC}\n"
    
    findings=$(aws macie2 list-findings \
        --region "$AWS_REGION" \
        --max-results 100 \
        --output json 2>/dev/null || echo "{}")
    
    if [ "$(echo "$findings" | jq '.findings | length' 2>/dev/null || echo 0)" -eq 0 ]; then
        print_success "No findings detected"
    else
        echo "$findings" | jq -r '.findings[] | "\(.findingArn): \(.title)"' 2>/dev/null || echo "Unable to parse findings"
    fi
}

################################################################################
# Create IAM Role for Lambda
################################################################################

create_lambda_role() {
    local role_name="${1:-MacieLambdaExecutionRole}"
    
    print_header "Creating IAM Role for Lambda: $role_name"
    
    # Check if role exists
    if aws iam get-role --role-name "$role_name" &>/dev/null; then
        print_warning "Role already exists: $role_name"
        return 0
    fi
    
    # Create role
    cat > /tmp/lambda_trust_policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
    
    aws iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document file:///tmp/lambda_trust_policy.json
    
    # Attach policies
    aws iam attach-role-policy \
        --role-name "$role_name" \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
    
    aws iam put-role-policy \
        --role-name "$role_name" \
        --policy-name MacieS3Policy \
        --policy-document file:///tmp/macie_policy.json 2>/dev/null || true
    
    print_success "IAM Role created: $role_name"
    aws iam get-role --role-name "$role_name" --query 'Role.Arn' --output text
    
    rm -f /tmp/lambda_trust_policy.json
}

################################################################################
# Export Configuration
################################################################################

export_bucket_config() {
    local bucket=$1
    local output_file="${SCRIPT_DIR}/bucket_config_${bucket}_$(date +%s).json"
    
    print_header "Exporting Configuration for: $bucket"
    
    cat > "$output_file" <<EOF
{
  "bucket": "$bucket",
  "exportDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "region": "$AWS_REGION",
  "encryption": $(aws s3api get-bucket-encryption --bucket "$bucket" --region "$AWS_REGION" 2>/dev/null || echo "{}"),
  "versioning": $(aws s3api get-bucket-versioning --bucket "$bucket" --region "$AWS_REGION" 2>/dev/null || echo "{}"),
  "publicAccessBlock": $(aws s3api get-public-access-block --bucket "$bucket" --region "$AWS_REGION" 2>/dev/null || echo "{}"),
  "logging": $(aws s3api get-bucket-logging --bucket "$bucket" --region "$AWS_REGION" 2>/dev/null || echo "{}"),
  "tagging": $(aws s3api get-bucket-tagging --bucket "$bucket" --region "$AWS_REGION" 2>/dev/null || echo "{}")
}
EOF
    
    print_success "Configuration exported to: $output_file"
}

################################################################################
# Help and Usage
################################################################################

show_usage() {
    cat <<EOF
${GREEN}AWS Macie Helper Utilities${NC}

${BLUE}Usage:${NC}
    ${0##*/} [COMMAND] [OPTIONS]

${BLUE}Commands:${NC}
    analyze <bucket>            Analyze bucket security configuration
    compliance <bucket>         Run compliance checks
    cost-estimate <bucket>      Estimate Macie and KMS costs
    find-unencrypted <bucket>   Find all unencrypted objects
    findings-summary            Get summary of Macie findings
    create-lambda-role          Create IAM role for Lambda automation
    export-config <bucket>      Export bucket configuration to JSON
    help                        Show this help message

${BLUE}Examples:${NC}
    ${0##*/} analyze my-bucket
    ${0##*/} compliance my-bucket
    ${0##*/} cost-estimate my-bucket
    ${0##*/} find-unencrypted my-bucket
    ${0##*/} findings-summary
    ${0##*/} export-config my-bucket

${BLUE}Environment Variables:${NC}
    AWS_REGION                  AWS region (default: us-east-1)
    AWS_PROFILE                 AWS profile to use

EOF
}

################################################################################
# Main
################################################################################

main() {
    local command=${1:-help}
    shift || true
    
    case "$command" in
        analyze)
            if [ $# -lt 1 ]; then
                print_error "Bucket name required"
                show_usage
                exit 1
            fi
            analyze_bucket_security "$1"
            ;;
        compliance)
            if [ $# -lt 1 ]; then
                print_error "Bucket name required"
                show_usage
                exit 1
            fi
            run_compliance_checks "$1"
            ;;
        cost-estimate)
            if [ $# -lt 1 ]; then
                print_error "Bucket name required"
                show_usage
                exit 1
            fi
            estimate_macie_costs "$1"
            ;;
        find-unencrypted)
            if [ $# -lt 1 ]; then
                print_error "Bucket name required"
                show_usage
                exit 1
            fi
            find_unencrypted_objects "$1"
            ;;
        findings-summary)
            get_findings_summary
            ;;
        create-lambda-role)
            create_lambda_role "${1:-MacieLambdaExecutionRole}"
            ;;
        export-config)
            if [ $# -lt 1 ]; then
                print_error "Bucket name required"
                show_usage
                exit 1
            fi
            export_bucket_config "$1"
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
