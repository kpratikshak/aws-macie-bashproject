# AWS Macie S3 Sensitive Data Detection & Encryption

This repository contains a comprehensive shell script for automating the detection and encryption of sensitive information in AWS S3 buckets using AWS Macie.

## Overview:

- **AWS Macie Integration**: Enable and manage Macie for sensitive data discovery
- **Automated Scanning**: Create and execute classification jobs on S3 buckets
- **Intelligent Encryption**: Apply SSE-S3 or SSE-KMS encryption based on requirements
- **Security Hardening**: Enable versioning, block public access, and MFA delete
- **Comprehensive Logging**: Detailed logs and remediation reports
- **Error Handling**: Robust error detection and recovery mechanisms

## Prerequisites

### AWS Requirements
- AWS Account with appropriate permissions (see IAM Policy section)
- AWS CLI v2 or later
- Configured AWS credentials (`aws configure`)
- S3 bucket(s) to scan and protect

### Local Requirements
- Bash 4.0+
- `jq` (optional, for JSON parsing)
- Appropriate file permissions

### Installation

```bash
# Clone or download the script
chmod +x aws_macie_s3_encrypt.sh

# Install jq (Ubuntu/Debian)
sudo apt-get install jq

# Configure AWS credentials
aws configure
```

## IAM Policy Requirements

Create an IAM policy or role with the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "MaciePermissions",
            "Effect": "Allow",
            "Action": [
                "macie2:EnableMacie",
                "macie2:GetMacieSession",
                "macie2:DisableMacie",
                "macie2:CreateClassificationJob",
                "macie2:ListClassificationJobs",
                "macie2:DescribeClassificationJob",
                "macie2:ListFindings",
                "macie2:GetFindings",
                "macie2:GetFindingsPublicationConfiguration",
                "macie2:UpdateFindingsPublicationConfiguration"
            ],
            "Resource": "*"
        },
        {
            "Sid": "S3Permissions",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject",
                "s3:GetBucketVersioning",
                "s3:PutBucketVersioning",
                "s3:GetBucketEncryption",
                "s3:PutBucketEncryption",
                "s3:GetBucketPolicy",
                "s3:GetPublicAccessBlock",
                "s3:PutPublicAccessBlock",
                "s3:ListAllMyBuckets"
            ],
            "Resource": [
                "arn:aws:s3:::*",
                "arn:aws:s3:::*/*"
            ]
        },
        {
            "Sid": "KMSPermissions",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey",
                "kms:CreateGrant",
                "kms:ListGrants",
                "kms:RevokeGrant"
            ],
            "Resource": "arn:aws:kms:*:*:key/*"
        },
        {
            "Sid": "STSPermissions",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchLogs",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
```

## Usage

### Basic Commands

```bash
# Show help
./aws_macie_s3_encrypt.sh --help

# Enable Macie
./aws_macie_s3_encrypt.sh --enable-macie

# Check Macie status
./aws_macie_s3_encrypt.sh --status

# List all Macie jobs
./aws_macie_s3_encrypt.sh --list-jobs
```

### Scan and Encrypt

```bash
# Create a scan job for a bucket
./aws_macie_s3_encrypt.sh --bucket my-bucket --create-job

# Enable encryption with SSE-S3 (AES-256)
./aws_macie_s3_encrypt.sh --bucket my-bucket --remediate

# Enable encryption with KMS
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678 \
    --remediate
```

### Full Workflow

```bash
# Complete setup: enable Macie, create job, and remediate findings
./aws_macie_s3_encrypt.sh \
    --enable-macie \
    --bucket my-sensitive-bucket \
    --kms-key-id arn:aws:kms:us-east-1:123456789012:key/abc123 \
    --create-job \
    --remediate
```

### Generate Reports

```bash
# Generate security and compliance report for a bucket
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --generate-report
```

## Environment Variables

```bash
# Specify AWS region (default: us-east-1)
export AWS_REGION=us-west-2
./aws_macie_s3_encrypt.sh --bucket my-bucket --remediate

# Use specific AWS profile
export AWS_PROFILE=production
./aws_macie_s3_encrypt.sh --enable-macie

# Combine both
export AWS_REGION=eu-west-1 AWS_PROFILE=prod-account
./aws_macie_s3_encrypt.sh --bucket my-bucket --remediate
```

## Output and Logs

The script generates comprehensive logs in the `logs/` directory:

```
logs/
├── macie_20240227_120000.log          # Main execution log
├── macie_report_20240227_120000.json  # Security report
└── macie_20240227_121530.log          # Another execution
```

### Log Format

```
[2024-02-27 12:00:00] [INFO] Logging initialized. Log file: logs/macie_20240227_120000.log
[2024-02-27 12:00:05] [SUCCESS] AWS Macie enabled successfully
[2024-02-27 12:00:10] [INFO] Creating AWS Macie scan job for bucket: my-bucket
[2024-02-27 12:00:15] [SUCCESS] Macie job created successfully. Job ID: 1234567890abcdef
```

## Encryption Options

### SSE-S3 (AES-256 Encryption)

**Pros:**
- No key management overhead
- Fast and reliable
- No additional KMS costs
- AWS managed

**Cons:**
- Limited control over keys
- Not suitable for highly sensitive data compliance requirements

**Usage:**
```bash
./aws_macie_s3_encrypt.sh --bucket my-bucket --remediate
```

### SSE-KMS (Customer Master Keys)

**Pros:**
- Full control over encryption keys
- Audit trail of key usage via CloudTrail
- Key rotation management
- Compliance with strict security policies

**Cons:**
- Additional KMS API costs
- Slight performance overhead
- Requires KMS key management

**Usage:**
```bash
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678 \
    --remediate
```

## What the Script Does

### 1. Enable Macie
- Activates AWS Macie for your account in the specified region
- Initializes Macie session and configuration

### 2. Create Classification Job
- Sets up an automated scan job for specified S3 bucket
- Configures scanning parameters and data classifiers
- Schedules discovery jobs to identify sensitive information

### 3. Remediate Findings
```
┌─────────────────────┐
│  Start Remediation  │
└──────────┬──────────┘
           │
     ┌─────▼─────┐
     │ Enable     │
     │ Encryption │────► Apply SSE-S3 or SSE-KMS
     └─────┬─────┘
           │
     ┌─────▼─────────┐
     │ Enable        │
     │ Versioning    │────► Protect against accidental deletion
     └─────┬─────────┘
           │
     ┌─────▼─────────────┐
     │ Encrypt ALL       │
     │ Unencrypted Objs  │────► Iterates through all objects
     └─────┬─────────────┘
           │
     ┌─────▼──────────┐
     │ Generate Report│────► Compliance documentation
     └─────┬──────────┘
           │
     ┌─────▼──────────────┐
     │ Remediation Done   │
     └────────────────────┘
```

### 4. Generate Reports
- Creates detailed JSON report with encryption status
- Documents bucket policies and security settings
- Provides compliance verification

## Security Best Practices

### 1. **Use KMS Encryption for Sensitive Data**
```bash
# Get your KMS key ARN
aws kms list-keys --region us-east-1

# Use in script
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --kms-key-id arn:aws:kms:us-east-1:123456789012:key/abc123 \
    --remediate
```

### 2. **Enable MFA Delete**
```bash
# Manually enable for additional protection
aws s3api put-bucket-versioning \
    --bucket my-bucket \
    --versioning-configuration Status=Enabled,MFADelete=Enabled \
    --mfa "device-serial-number code"
```

### 3. **Block Public Access**
```bash
aws s3api put-public-access-block \
    --bucket my-bucket \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 4. **Enable CloudTrail Logging**
```bash
# Audit all S3 access for compliance
aws cloudtrail start-logging --trail-name my-trail
```

### 5. **Configure Bucket Policies**
```bash
# Enforce encryption in transit
aws s3api put-bucket-policy \
    --bucket my-bucket \
    --policy file://ssl-policy.json
```

Example SSL enforcement policy:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyUnencryptedObjectUploads",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": [
                        "AES256",
                        "aws:kms"
                    ]
                }
            }
        },
        {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
```

## Troubleshooting

### Issue: "AWS credentials not configured"
```bash
# Solution: Configure AWS CLI
aws configure
# OR
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### Issue: "Macie is not enabled"
```bash
# Solution: Enable Macie in the account
./aws_macie_s3_encrypt.sh --enable-macie
```

### Issue: "Access Denied" errors
```bash
# Check IAM permissions
aws iam get-user
# Verify policy attachment
aws iam list-attached-user-policies --user-name your-user
```

### Issue: "Bucket not found"
```bash
# List available buckets
aws s3 ls

# Verify bucket name
aws s3api head-bucket --bucket my-bucket
```

### Issue: KMS Key Access Denied
```bash
# Verify KMS key ARN format
aws kms describe-key --key-id arn:aws:kms:region:account:key/id

# Check key policy
aws kms get-key-policy --key-id arn:aws:kms:region:account:key/id --policy-name default
```

## Advanced Usage

### Bulk Process Multiple Buckets

```bash
#!/bin/bash
# Process multiple buckets with KMS encryption

KMS_KEY="arn:aws:kms:us-east-1:123456789012:key/abc123"
BUCKETS=("bucket1" "bucket2" "bucket3")

for bucket in "${BUCKETS[@]}"; do
    echo "Processing bucket: $bucket"
    ./aws_macie_s3_encrypt.sh \
        --bucket "$bucket" \
        --kms-key-id "$KMS_KEY" \
        --remediate
    sleep 5  # Avoid rate limiting
done
```

### Scheduled Scans with Cron

```bash
# Add to crontab for weekly scans
0 2 * * 0 /path/to/aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --create-job >> /var/log/macie_scans.log 2>&1
```

### Integration with Lambda

```bash
# Invoke from Lambda
aws lambda invoke \
    --function-name MacieScanTrigger \
    --payload '{"bucket":"my-bucket"}' \
    response.json
```

## Monitoring and Compliance

### CloudWatch Metrics

The script logs to `/aws/macie/sensitive-data-scan` in CloudWatch. Monitor:
- Encryption status changes
- Job completion rates
- Finding counts
- Remediation actions

### Compliance Reporting

Generate reports for compliance frameworks:

```bash
# GDPR/CCPA Compliance Report
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --generate-report

# Store in compliance repository
cp logs/macie_report_*.json /compliance/reports/
```

## Cost Considerations

### Macie Pricing
- **Bucket analysis**: $1 per bucket-month
- **Object assessment**: $0.35 per 1,000 objects
- **S3 Classic**: $6 per Gb analyzed

### KMS Pricing
- **API calls**: $0.03 per 10,000 calls
- **Key storage**: $1 per key per month

### Estimation Example
For 1 bucket with 100GB of data:
- Macie: ~$1 (bucket) + ~$35 (objects) = **~$36/month**
- KMS: ~$0.30 (key) + ~$0.20 (API) = **~$0.50/month**
- **Total: ~$36.50/month**

## License

This script is provided as-is for AWS security automation.

## Support

For issues or questions:
1. Check AWS Macie documentation: https://docs.aws.amazon.com/macie/
2. Review AWS CLI documentation: https://docs.aws.amazon.com/cli/
3. Check CloudTrail logs for detailed error messages
4. Review script logs in `logs/` directory

## Additional Resources

- [AWS Macie User Guide](https://docs.aws.amazon.com/macie/latest/user/)
- [S3 Encryption Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingEncryption.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
