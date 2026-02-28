# AWS Macie S3 Encryption - Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Prerequisites Check
```bash
# Verify AWS CLI is installed
aws --version

# Verify credentials are configured
aws sts get-caller-identity

# Set your region (optional, defaults to us-east-1)
export AWS_REGION=us-east-1
```

### Step 2: Make Scripts Executable
```bash
chmod +x aws_macie_s3_encrypt.sh
chmod +x macie_helpers.sh
```

### Step 3: Quick Commands

#### Enable Macie
```bash
./aws_macie_s3_encrypt.sh --enable-macie
```

#### Scan and Encrypt a Bucket
```bash
# Using SSE-S3 (simple, no KMS)
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --create-job \
    --remediate

# Using KMS (more secure)
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --kms-key-id arn:aws:kms:us-east-1:123456:key/abc \
    --create-job \
    --remediate
```

## 📋 Common Operations

### Analyze Bucket Security
```bash
./macie_helpers.sh analyze my-bucket
```

Output shows:
- ✓ Encryption status
- ✓ Versioning enabled/disabled
- ✓ Public access block status
- ✓ Logging configuration
- ✓ Bucket policy status

### Run Compliance Checks
```bash
./macie_helpers.sh compliance my-bucket
```

Checks:
- [PASS/FAIL] Default encryption
- [PASS/FAIL] Versioning
- [PASS/FAIL] Public access blocked
- [PASS/FAIL] Server access logging
- [PASS/FAIL] Encryption enforced in policy

### Find Unencrypted Objects
```bash
./macie_helpers.sh find-unencrypted my-bucket
```

Creates file: `unencrypted_objects_TIMESTAMP.txt`

### Cost Estimation
```bash
./macie_helpers.sh cost-estimate my-bucket
```

Shows monthly and annual costs for:
- Macie scanning
- KMS key management

### Export Configuration
```bash
./macie_helpers.sh export-config my-bucket
```

Creates: `bucket_config_my-bucket_TIMESTAMP.json`

## 🔐 Encryption Options

### Option 1: SSE-S3 (AWS Managed Keys)
**Best for:** Non-sensitive workloads, quick setup
```bash
./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --remediate
```

**Pros:**
- No additional cost
- Simple management
- AWS handles all encryption

**Cons:**
- Limited control over keys
- No key rotation management
- Less suitable for compliance requirements

### Option 2: SSE-KMS (Customer Managed Keys)
**Best for:** Sensitive data, compliance requirements, HIPAA/PCI-DSS
```bash
# Get KMS key ARN
aws kms list-keys --region us-east-1 --query 'Keys[0].KeyArn' --output text

./aws_macie_s3_encrypt.sh \
    --bucket my-bucket \
    --kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678 \
    --remediate
```

**Pros:**
- Full control over encryption keys
- Audit trail via CloudTrail
- Compliance-ready
- Key rotation management

**Cons:**
- Additional KMS costs (~$1 key + API calls)
- Slightly more complex

## 📊 Full Workflow Example

```bash
#!/bin/bash

# Setup variables
export AWS_REGION=us-east-1
BUCKET_NAME="my-sensitive-data-bucket"
KMS_KEY="arn:aws:kms:us-east-1:123456789012:key/12345678"

# Step 1: Check current status
echo "🔍 Checking current bucket security..."
./macie_helpers.sh compliance "$BUCKET_NAME"

# Step 2: Cost estimation
echo "💰 Estimating costs..."
./macie_helpers.sh cost-estimate "$BUCKET_NAME"

# Step 3: Enable Macie (one-time)
echo "⚙️  Enabling Macie..."
./aws_macie_s3_encrypt.sh --enable-macie

# Step 4: Full remediation
echo "🔒 Applying encryption and security settings..."
./aws_macie_s3_encrypt.sh \
    --bucket "$BUCKET_NAME" \
    --kms-key-id "$KMS_KEY" \
    --create-job \
    --remediate

# Step 5: Verify results
echo "✅ Verifying..."
./macie_helpers.sh compliance "$BUCKET_NAME"

echo "✨ Done!"
```

## 🆘 Troubleshooting

### Error: "AWS credentials not configured"
```bash
# Configure AWS CLI
aws configure

# OR use environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### Error: "Access Denied"
```bash
# Check your IAM user permissions
aws iam get-user

# Verify Macie IAM policy is attached
aws iam list-attached-user-policies --user-name your-username
```

### Error: "Bucket not found"
```bash
# List available buckets
aws s3 ls

# Verify bucket exists and you have access
aws s3api head-bucket --bucket my-bucket
```

### Error: "KMS Key not found"
```bash
# List available KMS keys
aws kms list-keys --region us-east-1

# Get key ARN
aws kms describe-key --key-id key-id --region us-east-1
```

## 📈 Monitoring Progress

### Check Macie Job Status
```bash
./aws_macie_s3_encrypt.sh --list-jobs
```

Output:
```
Job ID          | Job Name              | Status
1234567890abc   | sensitive-data-scan   | RUNNING
```

### Check Encryption Status
```bash
# Check if bucket has default encryption
aws s3api get-bucket-encryption --bucket my-bucket

# Sample output:
# {
#     "Rules": [
#         {
#             "ApplyServerSideEncryptionByDefault": {
#                 "SSEAlgorithm": "aws:kms",
#                 "KMSMasterKeyID": "arn:aws:kms:..."
#             }
#         }
#     ]
# }
```

### View Logs
```bash
# List all logs
ls -lh logs/

# View latest log
tail -f logs/macie_*.log

# View specific report
cat logs/macie_report_*.json | jq '.'
```

## 🎯 Best Practices

### 1. Always Use Versioning
```bash
aws s3api put-bucket-versioning \
    --bucket my-bucket \
    --versioning-configuration Status=Enabled
```

### 2. Block Public Access
```bash
aws s3api put-public-access-block \
    --bucket my-bucket \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 3. Enforce Encryption in Bucket Policy
```bash
# Create policy file: bucket-policy.json
cat > bucket-policy.json <<'EOF'
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
                    "s3:x-amz-server-side-encryption": ["aws:kms"]
                }
            }
        },
        {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": ["arn:aws:s3:::my-bucket","arn:aws:s3:::my-bucket/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}
        }
    ]
}
EOF

# Apply policy
aws s3api put-bucket-policy \
    --bucket my-bucket \
    --policy file://bucket-policy.json
```

### 4. Enable MFA Delete
```bash
# Requires MFA device
aws s3api put-bucket-versioning \
    --bucket my-bucket \
    --versioning-configuration Status=Enabled,MFADelete=Enabled \
    --mfa "device-serial-number code"
```

### 5. Regular Audits
```bash
# Schedule weekly checks
(crontab -l 2>/dev/null; echo "0 2 * * 0 /path/to/macie_helpers.sh compliance my-bucket") | crontab -
```

## 📝 Cheat Sheet - Quick Commands

| Task | Command |
|------|---------|
| Enable Macie | `./aws_macie_s3_encrypt.sh --enable-macie` |
| Check Macie status | `./aws_macie_s3_encrypt.sh --status` |
| Scan bucket | `./aws_macie_s3_encrypt.sh --bucket my-bucket --create-job` |
| Remediate (encrypt) | `./aws_macie_s3_encrypt.sh --bucket my-bucket --remediate` |
| List all jobs | `./aws_macie_s3_encrypt.sh --list-jobs` |
| Analyze security | `./macie_helpers.sh analyze my-bucket` |
| Run compliance | `./macie_helpers.sh compliance my-bucket` |
| Find unencrypted | `./macie_helpers.sh find-unencrypted my-bucket` |
| Estimate costs | `./macie_helpers.sh cost-estimate my-bucket` |
| Export config | `./macie_helpers.sh export-config my-bucket` |
| Get findings | `./macie_helpers.sh findings-summary` |

## 🔗 Useful Links

- [AWS Macie Docs](https://docs.aws.amazon.com/macie/)
- [S3 Encryption Guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingEncryption.html)
- [KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)

## 📞 Support

**In case of issues:**

1. **Check logs** - All activity is logged to `logs/` directory
2. **Verify credentials** - Run `aws sts get-caller-identity`
3. **Check IAM permissions** - Review IAM policy requirements in the main README
4. **CloudTrail** - Check CloudTrail for detailed API logs
5. **AWS Support** - Contact AWS Support if issues persist

## ✅ Verification Checklist

After running the scripts, verify:

- [ ] Macie is enabled: `aws macie2 get-macie-session`
- [ ] Bucket has default encryption: `aws s3api get-bucket-encryption --bucket my-bucket`
- [ ] Versioning is enabled: `aws s3api get-bucket-versioning --bucket my-bucket`
- [ ] Public access is blocked: `aws s3api get-public-access-block --bucket my-bucket`
- [ ] Compliance checks pass: `./macie_helpers.sh compliance my-bucket`
- [ ] No errors in logs: `grep ERROR logs/macie_*.log`

---

**Last Updated:** February 2024
**Version:** 1.0
**License:** MIT
